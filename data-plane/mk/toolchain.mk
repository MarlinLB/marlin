# Toolchain preflight for the data-plane build. Split out of ../Makefile
# because the probe logic below is well past inline-length.
#
# check-toolchain has two severities (MARLIN_CHECK_STRICT below): standalone
# makes every probe fatal; as a prerequisite, Group A stays fatal but Group B (format/tidy) only warns.
#
# No cache/stamp file: every probe re-runs each invocation so it cannot go
# stale. check-toolchain is .PHONY for that reason.
#
# .ONESHELL is required: without it make runs each physical recipe line as
# its own shell invocation, shredding the heredoc script below.
.ONESHELL:

# Standalone means check-toolchain was named explicitly on the command line;
# a MAKECMDGOALS text check, not a parse-time capability probe.
ifneq ($(filter check-toolchain,$(MAKECMDGOALS)),)
MARLIN_CHECK_STRICT := 1
else
MARLIN_CHECK_STRICT := 0
endif

# The repo root, so probes 8/9 can point --style=file:/--config-file= at the
# real configs explicitly; both tools search upward and would pass vacuously otherwise.
MARLIN_REPO_ROOT := $(abspath $(CURDIR)/..)

# The probe script. POSIX sh; every configurable piece arrives via the
# environment so this text needs no editing to test with stubs.
define MARLIN_CHECK_TOOLCHAIN_SCRIPT
set -u

: "$${CLANG:=clang}"
: "$${BPFTOOL:=bpftool}"
: "$${READELF:=}"
: "$${CLANG_FORMAT:=clang-format}"
: "$${CLANG_TIDY:=clang-tidy}"
: "$${MARLIN_CHECK_STRICT:=0}"
: "$${REPO_ROOT:=..}"

tmpdir=$$(mktemp -d "$${TMPDIR:-/tmp}/marlin-check-toolchain.XXXXXX") || {
	echo "check-toolchain: cannot create a temp directory" >&2
	exit 1
}
trap 'rm -rf "$$tmpdir"' EXIT HUP INT TERM

overall=0

say()  { printf 'checking %s... ' "$$1" >&2; }
pass() { printf 'yes\n' >&2; }
warn_missing() {
	# Group B, non-strict: tool absent/too old, build proceeds.
	printf 'no (style checks unavailable)\n' >&2
}

# $$1 requirement text   $$2 command run   $$3 log file   $$4 suggested fix
fail() {
	printf 'no\n' >&2
	{
		printf 'error: %s\n' "$$1"
		printf '  command: %s\n' "$$2"
		printf '  output:\n'
		sed 's/^/    /' "$$3"
		printf '  likely fix: %s\n' "$$4"
	} >&2
	overall=1
}

# Locate a readelf/objdump-family tool for probes 2 and 4 (READELF override,
# else first found on PATH); echoes "<tool>:<kind>", empty if none found.
find_inspect_tool() {
	if [ -n "$$READELF" ]; then
		if command -v "$$READELF" >/dev/null 2>&1; then
			case "$$READELF" in
			*objdump*) printf '%s:objdump\n' "$$READELF" ;;
			*) printf '%s:readelf\n' "$$READELF" ;;
			esac
		fi
		return 0
	fi
	for cand in llvm-readelf readelf llvm-objdump; do
		if command -v "$$cand" >/dev/null 2>&1; then
			case "$$cand" in
			*objdump*) printf '%s:objdump\n' "$$cand" ;;
			*) printf '%s:readelf\n' "$$cand" ;;
			esac
			return 0
		fi
	done
	return 0
}

# ============================================================================
# Group A -- build prerequisites. Always fatal.
# ============================================================================

# --- Probe 1: clang -target bpf -------------------------------------------
say "whether \$$CLANG ($${CLANG}) accepts -target bpf"
p1_src="$$tmpdir/p1.c"
p1_obj="$$tmpdir/p1.o"
cat >"$$p1_src" <<'EOF'
int marlin_toolchain_probe(void) { return 0; }
EOF
if "$$CLANG" -target bpf -c "$$p1_src" -o "$$p1_obj" >"$$tmpdir/p1.log" 2>&1; then
	pass
	p1_ok=1
else
	fail "clang must compile for -target bpf" \
		"$$CLANG -target bpf -c $$p1_src -o $$p1_obj" "$$tmpdir/p1.log" \
		"install/upgrade clang with the BPF backend built in (LLVM >= 12); Debian/Ubuntu: apt install clang"
	p1_ok=0
fi

# --- Probe 2: -mcpu=v3 actually generates BPF_CMPXCHG ----------------------
say "whether \$$CLANG -mcpu=v3 emits BPF_ATOMIC|BPF_CMPXCHG"
p2_src="$$tmpdir/p2.c"
p2_obj="$$tmpdir/p2.o"
cat >"$$p2_src" <<'EOF'
typedef unsigned long long __u64;
__u64 marlin_toolchain_probe_cas(__u64 *p, __u64 old, __u64 new)
{
	return __sync_val_compare_and_swap(p, old, new);
}
EOF
if ! "$$CLANG" -target bpf -mcpu=v3 -c "$$p2_src" -o "$$p2_obj" >"$$tmpdir/p2.log" 2>&1; then
	fail "clang must accept -mcpu=v3 (required by ratelimit.c's compare-and-swap)" \
		"$$CLANG -target bpf -mcpu=v3 -c $$p2_src -o $$p2_obj" "$$tmpdir/p2.log" \
		"upgrade clang -- -mcpu=v3 needs LLVM's BPF v3 ISA support"
else
	# Compiling is not proof: some clang accepts an unrecognised -mcpu with only
	# a warning and silently falls back, so inspect the actual bytes.
	tool_spec=$$(find_inspect_tool)
	if [ -z "$$tool_spec" ]; then
		fail "no readelf/objdump-family tool found to verify BPF_CMPXCHG codegen" \
			"(would run: <llvm-readelf|readelf> -x .text $$p2_obj)" /dev/null \
			"install binutils (readelf) or llvm (llvm-readelf); or set READELF explicitly"
	else
		tool=$${tool_spec%%:*}
		kind=$${tool_spec##*:}
		if [ "$$kind" = objdump ]; then
			hex=$$("$$tool" -s -j .text "$$p2_obj" 2>"$$tmpdir/p2insp.log" | awk '/^ [0-9a-f]+ /{ $$1=""; print }' | tr -d ' \n')
		else
			hex=$$("$$tool" -x .text "$$p2_obj" 2>"$$tmpdir/p2insp.log" | awk '/0x[0-9a-f]+ /{ $$1=""; NF--; print }' | tr -d ' \n')
		fi
		# BPF_ATOMIC opcode (0xdb 64-bit / 0xc3 32-bit), regs+offset byte, then
		# BPF_CMPXCHG's imm byte (0xf1) -- linux/bpf.h's encoding.
		if printf '%s' "$$hex" | grep -Eqi '(db|c3)[0-9a-f]{6}f1'; then
			pass
		else
			fail "clang -mcpu=v3 compiled but emitted no BPF_CMPXCHG instruction (accepted the flag and silently fell back)" \
				"$$CLANG -target bpf -mcpu=v3 -c $$p2_src -o $$p2_obj && $$tool -x .text $$p2_obj" \
				"$$tmpdir/p2insp.log" \
				"upgrade clang; -mcpu=v3 is recognised but this build's BPF backend does not lower __sync_val_compare_and_swap to BPF_CMPXCHG"
		fi
	fi
fi

# --- Probe 3: <bpf/bpf_helpers.h> resolves ---------------------------------
say "whether #include <bpf/bpf_helpers.h> resolves"
p3_src="$$tmpdir/p3.c"
cat >"$$p3_src" <<'EOF'
#include <bpf/bpf_helpers.h>
EOF
# -E: preprocess only, to check header search-path resolution without also
# requiring __u64 and friends already in scope (a separate concern).
if "$$CLANG" -target bpf -E "$$p3_src" -o /dev/null >"$$tmpdir/p3.log" 2>&1; then
	pass
else
	fail "<bpf/bpf_helpers.h> does not resolve (every marlin_* translation unit needs it)" \
		"$$CLANG -target bpf -E $$p3_src -o /dev/null" "$$tmpdir/p3.log" \
		"install libbpf-dev (Debian/Ubuntu) / libbpf-devel (Fedora/RHEL), or add -I to its headers"
fi

# --- Probe 4: -g compile carries a .BTF section ----------------------------
say "whether a clang -g object carries a .BTF section"
p4_src="$$tmpdir/p4.c"
p4_obj="$$tmpdir/p4.o"
cat >"$$p4_src" <<'EOF'
typedef unsigned long long __u64;
struct marlin_toolchain_probe_ctx { __u64 data; __u64 data_end; };
int marlin_toolchain_probe_xdp(struct marlin_toolchain_probe_ctx *ctx) { return 2; }
EOF
if ! "$$CLANG" -target bpf -g -c "$$p4_src" -o "$$p4_obj" >"$$tmpdir/p4.log" 2>&1; then
	fail "clang -g must compile for -target bpf" \
		"$$CLANG -target bpf -g -c $$p4_src -o $$p4_obj" "$$tmpdir/p4.log" \
		"same fix as probe 1 -- this is the same clang, with debug info turned on"
else
	tool_spec=$$(find_inspect_tool)
	if [ -z "$$tool_spec" ]; then
		fail "no readelf/objdump-family tool found to check for a .BTF section" \
			"(would run: <llvm-readelf|readelf|llvm-objdump> against $$p4_obj)" /dev/null \
			"install binutils (readelf) or llvm (llvm-readelf/llvm-objdump); or set READELF explicitly"
	else
		tool=$${tool_spec%%:*}
		kind=$${tool_spec##*:}
		if [ "$$kind" = objdump ]; then
			sections=$$("$$tool" -h "$$p4_obj" 2>"$$tmpdir/p4insp.log")
		else
			sections=$$("$$tool" -S "$$p4_obj" 2>"$$tmpdir/p4insp.log")
		fi
		if printf '%s' "$$sections" | grep -q '\.BTF'; then
			pass
		else
			fail "clang -g produced no .BTF section (BTF is required on every input)" \
				"$$tool -S $$p4_obj  (or -h for llvm-objdump)" "$$tmpdir/p4insp.log" \
				"upgrade clang -- BTF-from-DWARF generation for the bpf target needs LLVM >= 12"
		fi
	fi
fi

# --- Probe 5: bpftool gen object links a BTF-carrying input ----------------
say "whether \$$BPFTOOL ($${BPFTOOL}) gen object links"
p5_out="$$tmpdir/p5-linked.o"
if [ "$${p1_ok}" = 1 ] && [ -s "$$p4_obj" ]; then
	if "$$BPFTOOL" gen object "$$p5_out" "$$p4_obj" >"$$tmpdir/p5.log" 2>&1; then
		pass
	else
		fail "bpftool gen object must link a BTF-carrying .o (libbpf's bpf_linker)" \
			"$$BPFTOOL gen object $$p5_out $$p4_obj" "$$tmpdir/p5.log" \
			"upgrade bpftool/libbpf -- gen object needs libbpf >= 0.4's static linker; on Debian/Ubuntu: apt install linux-tools-\$$(uname -r) or bpftool from your kernel's linux-tools package"
	fi
else
	fail "bpftool gen object was not attempted -- probe 4's object is unavailable" \
		"(skipped)" /dev/null \
		"fix probe 4 first; probe 5 depends on the object it produces"
fi

# ============================================================================
# Group B -- style prerequisites. Fatal only when invoked standalone.
# ============================================================================

group_b_fail=0

style_fail() {
	# Same shape as fail(), but severity depends on MARLIN_CHECK_STRICT.
	if [ "$$MARLIN_CHECK_STRICT" = 1 ]; then
		fail "$$1" "$$2" "$$3" "$$4"
	else
		warn_missing
		printf '  (%s -- not enforced for this build; run `make check-toolchain` to see it as an error)\n' "$$1" >&2
	fi
	group_b_fail=1
}

# --- Probe 6: clang-format >= 16 -------------------------------------------
say "for \$$CLANG_FORMAT ($${CLANG_FORMAT}) >= 16"
if ! command -v "$$CLANG_FORMAT" >/dev/null 2>&1; then
	style_fail "clang-format not found (.clang-format:21 requires >= 16 for InsertBraces/InsertNewlineAtEOF/RemoveSemicolon)" \
		"command -v $$CLANG_FORMAT" /dev/null \
		"install clang-format >= 16, e.g. apt install clang-format-18"
else
	cf_ver_raw=$$("$$CLANG_FORMAT" --version 2>"$$tmpdir/cf_ver.log")
	cf_major=$$(printf '%s' "$$cf_ver_raw" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
	if [ -z "$$cf_major" ]; then
		style_fail "clang-format --version did not report a parseable version" \
			"$$CLANG_FORMAT --version" "$$tmpdir/cf_ver.log" \
			"check that $$CLANG_FORMAT is really clang-format and not a shim"
	elif [ "$$cf_major" -lt 16 ]; then
		{
			printf 'clang-format %s found, .clang-format:21 requires >= 16\n' "$$cf_major"
		} >"$$tmpdir/cf_ver_fail.log"
		style_fail "clang-format is older than the floor .clang-format:21 documents" \
			"$$CLANG_FORMAT --version" "$$tmpdir/cf_ver_fail.log" \
			"upgrade to clang-format >= 16 (found major version $$cf_major)"
	else
		pass
	fi
fi

# --- Probe 7: clang-tidy >= 19 ----------------------------------------------
say "for \$$CLANG_TIDY ($${CLANG_TIDY}) >= 18"
if ! command -v "$$CLANG_TIDY" >/dev/null 2>&1; then
	style_fail "clang-tidy not found (.clang-tidy:12 requires >= 18 for ExcludeHeaderFilterRegex)" \
		"command -v $$CLANG_TIDY" /dev/null \
		"install clang-tidy >= 18, e.g. apt install clang-tidy-18"
else
	ct_ver_raw=$$("$$CLANG_TIDY" --version 2>"$$tmpdir/ct_ver.log")
	ct_major=$$(printf '%s' "$$ct_ver_raw" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
	if [ -z "$$ct_major" ]; then
		style_fail "clang-tidy --version did not report a parseable version" \
			"$$CLANG_TIDY --version" "$$tmpdir/ct_ver.log" \
			"check that $$CLANG_TIDY is really clang-tidy and not a shim"
	elif [ "$$ct_major" -lt 18 ]; then
		{
			printf 'clang-tidy %s found, .clang-tidy:12 requires >= 18\n' "$$ct_major"
		} >"$$tmpdir/ct_ver_fail.log"
		style_fail "clang-tidy is older than the floor .clang-tidy:12 documents" \
			"$$CLANG_TIDY --version" "$$tmpdir/ct_ver_fail.log" \
			"upgrade to clang-tidy >= 18 (found major version $$ct_major)"
	else
		pass
	fi
fi

# --- Probe 8: clang-format actually reads .clang-format --------------------
say "whether \$$CLANG_FORMAT reads $$REPO_ROOT/.clang-format cleanly"
if ! command -v "$$CLANG_FORMAT" >/dev/null 2>&1; then
	style_fail "skipped -- clang-format is not present (see probe 6)" "(skipped)" /dev/null \
		"fix probe 6 first"
else
	# Point --style=file: at the real config explicitly (a bare temp dir would
	# find nothing and pass vacuously); format one real byte so no-op can't pass.
	p8_c="$$tmpdir/p8.c"
	printf 'int x;\n' >"$$p8_c"
	if "$$CLANG_FORMAT" "--style=file:$${REPO_ROOT}/.clang-format" "$$p8_c" >"$$tmpdir/p8.out" 2>"$$tmpdir/p8.log"; then
		if [ -s "$$tmpdir/p8.log" ]; then
			style_fail ".clang-format:24-30's pre-17 option spellings are not all recognised by this clang-format (it degrades to defaults instead of erroring, and then formats differently from CI)" \
				"$$CLANG_FORMAT --style=file:$${REPO_ROOT}/.clang-format $$p8_c" "$$tmpdir/p8.log" \
				"install a clang-format matched to .clang-format's comment (14-21); the config deliberately targets that range"
		else
			pass
		fi
	else
		style_fail ".clang-format could not be read at all by this clang-format" \
			"$$CLANG_FORMAT --style=file:$${REPO_ROOT}/.clang-format $$p8_c" "$$tmpdir/p8.log" \
			"install a clang-format matched to .clang-format's comment (14-21)"
	fi
fi

# --- Probe 9: clang-tidy --verify-config accepts .clang-tidy ---------------
say "whether \$$CLANG_TIDY --verify-config accepts $$REPO_ROOT/.clang-tidy"
if ! command -v "$$CLANG_TIDY" >/dev/null 2>&1; then
	style_fail "skipped -- clang-tidy is not present (see probe 7)" "(skipped)" /dev/null \
		"fix probe 7 first"
else
	if "$$CLANG_TIDY" --verify-config "--config-file=$${REPO_ROOT}/.clang-tidy" >"$$tmpdir/p9.log" 2>&1; then
		pass
	else
		style_fail ".clang-tidy is not accepted by clang-tidy --verify-config (note: .clang-tidy:72 sets FormatStyle: file, so this also depends on probe 8 passing)" \
			"$$CLANG_TIDY --verify-config --config-file=$${REPO_ROOT}/.clang-tidy" "$$tmpdir/p9.log" \
			"upgrade clang-tidy to >= 19, or see the .clang-tidy diagnostic above for the exact rejected key"
	fi
fi

# ============================================================================
if [ "$$overall" = 1 ]; then
	exit 1
fi
if [ "$$MARLIN_CHECK_STRICT" = 1 ] && [ "$$group_b_fail" = 1 ]; then
	exit 1
fi
exit 0

endef

# One recipe line: sh reads the script from its own heredoc, keeping every
# probe's shell code in one file without breaking make's recipe-tab rule.
define MARLIN_CHECK_TOOLCHAIN_INVOKE
sh -s <<'MARLIN_CHECK_TOOLCHAIN_EOF'
$(MARLIN_CHECK_TOOLCHAIN_SCRIPT)
MARLIN_CHECK_TOOLCHAIN_EOF
endef

.PHONY: check-toolchain
check-toolchain:
	@CLANG='$(CLANG)' BPFTOOL='$(BPFTOOL)' READELF='$(READELF)' CLANG_FORMAT='$(CLANG_FORMAT)' CLANG_TIDY='$(CLANG_TIDY)' MARLIN_CHECK_STRICT='$(MARLIN_CHECK_STRICT)' REPO_ROOT='$(MARLIN_REPO_ROOT)' $(MARLIN_CHECK_TOOLCHAIN_INVOKE)
