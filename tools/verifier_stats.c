/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Loads marlin.bpf.o with verifier logging and reports the two figures
 * docs/design/05-budgets.md tracks: processed instructions against the
 * 1,000,000 verifier limit, and the worst combined stack depth against the
 * 512-byte MAX_BPF_STACK limit. Deliberately does not pin anything:
 * bpf_object__load() keeps program fds open in this process, closed on
 * exit, so nothing under /sys/fs/bpf is ever touched -- unlike `bpftool
 * prog load`/`loadall`, whose pinning step some hosts' LSM policy blocks
 * even under root.
 *
 * Requests BPF_LOG_LEVEL1 (bit 0) and BPF_LOG_STATS (bit 2) only, never
 * BPF_LOG_LEVEL2 (bit 1): level 2 adds a fully annotated instruction-by-
 * instruction trace with a register-state dump on every line, for every
 * subprogram, whether or not the load fails -- tens of thousands of lines
 * for an object this size, none of which this program reads. Level 1 alone
 * already carries everything parsed below: the per-subprogram "is safe"
 * lines, "stack depth ...", and "processed ... insns".
 *
 * The kernel's "stack depth" log line lists one figure per BPF-to-BPF
 * callable function -- each function's own worst-case depth if execution
 * starts there, in verifier subprog order, with no names and no call-graph
 * information attached. It used to be read as this program's answer under
 * the assumption that Marlin's units are only ever called as siblings of
 * xdp_main. balancer.c ended that: marlin_balancer_process() calls the
 * three encapsulation units and both marlin_nexthop_*() entry points
 * directly, so a real three-frame chain exists (xdp_main ->
 * marlin_balancer_process -> marlin_vxlan_encap_packet) and neither the
 * max nor the sum of the kernel's flat list is the figure MAX_BPF_STACK is
 * checked against -- that figure is the deepest root-to-leaf sum of
 * per-function frames along the actual call graph.
 *
 * This program reconstructs that call graph itself, straight from the
 * relinked object's ELF: R_BPF_64_32 relocations are exactly the
 * BPF-to-BPF call sites bpftool gen object leaves for libbpf to resolve,
 * so reading them gives caller/callee edges with real function names
 * attached, and per-function stack depth is recovered by decoding each
 * function's own instructions for r10-relative stack references -- the
 * same quantity the verifier's stack_depth is, computed the same way
 * (round_up to 16 bytes under the JIT, 32 bytes otherwise). The kernel's
 * anonymous per-function list is still printed alongside, for cross-
 * checking against the two figures below it, but it is no longer the
 * reported answer.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MARLIN_MAX_BPF_STACK       512
#define MARLIN_VERIFIER_INSN_LIMIT 1000000
#define LOG_BUF_SIZE               (8 * 1024 * 1024)

/* Failures only: the verifier log is read from the buffer below, not this callback. */
static int print_diagnostics(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if(level > LIBBPF_WARN) {
        return 0;
    }

    return vfprintf(stderr, fmt, args);
}

static long parse_processed_insns(const char *log)
{
    static const char needle[] = "processed ";
    const char *p = strstr(log, needle);

    if(p == NULL) {
        return -1;
    }

    return strtol(p + sizeof(needle) - 1, NULL, 10);
}

/*
 * Prints each "stack depth A+B+C+..." figure on its own line. Kept for
 * cross-checking the ELF-derived depths below against the kernel's own
 * count of subprograms; no longer the source of the reported figure (see
 * file header).
 */
static void report_stack_depth(const char *log)
{
    static const char needle[] = "stack depth ";
    const char *p = strstr(log, needle);
    char *line;
    char *tok;
    char *saveptr;
    char *newline;
    long val;
    int idx = 0;

    if(p == NULL) {
        printf("Per-function stack depth (kernel log): not found\n");
        return;
    }

    line = strdup(p + sizeof(needle) - 1);
    if(line == NULL) {
        return;
    }

    newline = strchr(line, '\n');
    if(newline != NULL) {
        *newline = '\0';
    }

    printf("Per-function worst-case stack depth if execution starts there, kernel subprog "
           "order, no names (bytes):\n");

    for(tok = strtok_r(line, "+", &saveptr); tok != NULL; tok = strtok_r(NULL, "+", &saveptr)) {
        val = strtol(tok, NULL, 10);
        printf("  subprog #%d: %ld\n", idx, val);
        idx++;
    }

    free(line);
}

/* ---- Call-graph reconstruction straight from the ELF ------------------- */

#define MARLIN_MAX_FUNCS 256
#define MARLIN_MAX_EDGES 1024
#define MARLIN_MAX_NAME  128

struct marlin_func {
    char name[MARLIN_MAX_NAME];
    int sec_idx;
    Elf64_Addr value; /* byte offset within sec_idx -- sections hold several
                        * functions apiece, so this is what a relocation's
                        * r_offset must be matched against, not sec_idx alone */
    Elf64_Xword size;
    long stack_depth;
};

struct marlin_edge {
    int caller;
    int callee;
};

static struct marlin_func g_funcs[MARLIN_MAX_FUNCS];
static int g_nfuncs;
static struct marlin_edge g_edges[MARLIN_MAX_EDGES];
static int g_nedges;

static int find_func_by_name(const char *name)
{
    for(int i = 0; i < g_nfuncs; i++) {
        if(strcmp(g_funcs[i].name, name) == 0) {
            return i;
        }
    }

    return -1;
}

static void add_edge(int caller, int callee)
{
    if(caller < 0 || callee < 0) {
        return;
    }

    for(int i = 0; i < g_nedges; i++) {
        if(g_edges[i].caller == caller && g_edges[i].callee == callee) {
            return; /* already recorded, e.g. two call sites to the same callee */
        }
    }

    if(g_nedges >= MARLIN_MAX_EDGES) {
        fprintf(stderr, "verifier-stats: MARLIN_MAX_EDGES exceeded, call graph truncated\n");
        return;
    }

    g_edges[g_nedges].caller = caller;
    g_edges[g_nedges].callee = callee;
    g_nedges++;
}

/*
 * Decodes one function's own instructions for r10-relative stack
 * references: direct loads/stores based on r10, and the "rX = r10; rX +=
 * -N" idiom clang emits to take a local's address. This is the same
 * quantity the verifier tracks as a subprog's stack_depth -- the deepest
 * byte offset below the frame pointer the function itself ever touches.
 */
static long decode_stack_depth(const struct bpf_insn *insns, size_t n)
{
    long max_off = 0;
    int mov_r10_dst = -1;

    for(size_t i = 0; i < n; i++) {
        struct bpf_insn insn = insns[i];
        __u8 class = (__u8)(insn.code & 0x07);
        int is_stack_ref = 0;
        long off = 0;

        if(class == BPF_LDX && insn.src_reg == BPF_REG_10) {
            is_stack_ref = 1;
            off = insn.off;
        } else if((class == BPF_STX || class == BPF_ST) && insn.dst_reg == BPF_REG_10) {
            is_stack_ref = 1;
            off = insn.off;
        }

        if(is_stack_ref && off < 0 && -off > max_off) {
            max_off = -off;
        }

        if(insn.code == (BPF_ALU64 | BPF_MOV | BPF_X) && insn.src_reg == BPF_REG_10) {
            mov_r10_dst = insn.dst_reg;
            continue;
        }

        if(mov_r10_dst >= 0 && insn.code == BPF_ALU64 && insn.dst_reg == mov_r10_dst && insn.imm < 0) {
            if(-(long)insn.imm > max_off) {
                max_off = -(long)insn.imm;
            }
        }

        mov_r10_dst = -1;
    }

    return max_off;
}

/*
 * Walks every section's symbol table and relocations to rebuild the
 * BPF-to-BPF call graph and each subprogram's own stack depth. Pure ELF
 * reading -- no privilege needed, unlike bpf_object__load() below.
 */
static int build_call_graph(const char *path)
{
    int fd;
    Elf *elf;
    size_t shstrndx;
    Elf_Scn *scn;
    GElf_Shdr shdr;
    Elf_Scn *symtab_scn = NULL;
    GElf_Shdr symtab_shdr;
    int ret = -1;

    if(elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "verifier-stats: libelf version mismatch\n");
        return -1;
    }

    fd = open(path, O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "verifier-stats: open %s for ELF analysis: %s\n", path, strerror(errno));
        return -1;
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if(elf == NULL) {
        fprintf(stderr, "verifier-stats: elf_begin failed: %s\n", elf_errmsg(-1));
        close(fd);
        return -1;
    }

    if(elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "verifier-stats: elf_getshdrstrndx failed: %s\n", elf_errmsg(-1));
        goto out;
    }

    scn = NULL;
    while((scn = elf_nextscn(elf, scn)) != NULL) {
        if(gelf_getshdr(scn, &shdr) == NULL) {
            continue;
        }

        if(shdr.sh_type == SHT_SYMTAB) {
            symtab_scn = scn;
            symtab_shdr = shdr;
            break;
        }
    }

    if(symtab_scn == NULL) {
        fprintf(stderr, "verifier-stats: no symbol table in %s\n", path);
        goto out;
    }

    /* Pass 1: every STT_FUNC symbol with a body is a BPF-to-BPF subprogram. */
    {
        Elf_Data *symdata = elf_getdata(symtab_scn, NULL);
        size_t nsyms = symtab_shdr.sh_size / symtab_shdr.sh_entsize;

        for(size_t i = 0; i < nsyms; i++) {
            GElf_Sym sym;
            const char *name;

            if(gelf_getsym(symdata, (int)i, &sym) == NULL) {
                continue;
            }

            if(GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_size == 0) {
                continue;
            }

            name = elf_strptr(elf, symtab_shdr.sh_link, sym.st_name);
            if(name == NULL || name[0] == '\0') {
                continue;
            }

            if(g_nfuncs >= MARLIN_MAX_FUNCS) {
                fprintf(stderr, "verifier-stats: MARLIN_MAX_FUNCS exceeded\n");
                goto out;
            }

            /* Decode this function's own instructions for its stack depth. */
            {
                Elf_Scn *fscn = elf_getscn(elf, sym.st_shndx);
                Elf_Data *fdata = fscn != NULL ? elf_getdata(fscn, NULL) : NULL;

                if(fdata == NULL || sym.st_value + sym.st_size > fdata->d_size) {
                    fprintf(stderr, "verifier-stats: %s: symbol out of bounds of its section\n", name);
                    continue;
                }

                snprintf(g_funcs[g_nfuncs].name, sizeof(g_funcs[g_nfuncs].name), "%s", name);
                g_funcs[g_nfuncs].sec_idx = sym.st_shndx;
                g_funcs[g_nfuncs].value = sym.st_value;
                g_funcs[g_nfuncs].size = sym.st_size;
                g_funcs[g_nfuncs].stack_depth =
                    decode_stack_depth((const struct bpf_insn *)((const char *)fdata->d_buf + sym.st_value), sym.st_size / sizeof(struct bpf_insn));
                g_nfuncs++;
            }
        }
    }

    /* Pass 2: every R_BPF_64_32 relocation is a call site -- caller found by
     * offset within the target section, callee named by the relocation's
     * symbol. R_BPF_64_64 relocations are map/data references, not calls,
     * and are skipped.
     */
    scn = NULL;
    while((scn = elf_nextscn(elf, scn)) != NULL) {
        Elf_Data *reldata;
        size_t nrels;
        int target_sec;

        if(gelf_getshdr(scn, &shdr) == NULL || shdr.sh_type != SHT_REL) {
            continue;
        }

        target_sec = (int)shdr.sh_info;
        reldata = elf_getdata(scn, NULL);
        nrels = shdr.sh_size / shdr.sh_entsize;

        for(size_t i = 0; i < nrels; i++) {
            GElf_Rel rel;
            GElf_Sym sym;
            const char *callee_name;
            int caller_idx = -1;
            int callee_idx;

            if(gelf_getrel(reldata, (int)i, &rel) == NULL) {
                continue;
            }

            if(GELF_R_TYPE(rel.r_info) != R_BPF_64_32) {
                continue;
            }

            if(gelf_getsym(elf_getdata(symtab_scn, NULL), (int)GELF_R_SYM(rel.r_info), &sym) == NULL) {
                continue;
            }

            callee_name = elf_strptr(elf, symtab_shdr.sh_link, sym.st_name);
            if(callee_name == NULL) {
                continue;
            }

            callee_idx = find_func_by_name(callee_name);
            if(callee_idx < 0) {
                continue; /* relocation against something other than a known subprogram */
            }

            /* Caller: whichever known function's byte range in target_sec
             * contains r_offset -- a section holds several subprograms'
             * worth of code apiece (e.g. every TU's global functions land
             * in one shared .text), so sec_idx alone does not identify it.
             */
            for(int f = 0; f < g_nfuncs; f++) {
                if(g_funcs[f].sec_idx != target_sec) {
                    continue;
                }

                if((Elf64_Addr)rel.r_offset < g_funcs[f].value || (Elf64_Addr)rel.r_offset >= g_funcs[f].value + g_funcs[f].size) {
                    continue;
                }

                caller_idx = f;
                break;
            }

            add_edge(caller_idx, callee_idx);
        }
    }

    ret = 0;

out:
    elf_end(elf);
    close(fd);
    return ret;
}

/*
 * Finds the XDP entry point: the one function symbol whose section is
 * literally named "xdp" or "xdp/..." (SEC("xdp...") in main.c). Marlin
 * builds exactly one BPF program per object, so exactly one match is
 * expected.
 */
static int find_entry_func(const char *path)
{
    int fd;
    Elf *elf;
    size_t shstrndx;
    int entry = -1;

    fd = open(path, O_RDONLY);
    if(fd < 0) {
        return -1;
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if(elf == NULL || elf_getshdrstrndx(elf, &shstrndx) != 0) {
        if(elf != NULL) {
            elf_end(elf);
        }

        close(fd);
        return -1;
    }

    for(int f = 0; f < g_nfuncs; f++) {
        Elf_Scn *scn = elf_getscn(elf, g_funcs[f].sec_idx);
        GElf_Shdr shdr;
        const char *secname;

        if(scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
            continue;
        }

        secname = elf_strptr(elf, shstrndx, shdr.sh_name);
        if(secname != NULL && (strcmp(secname, "xdp") == 0 || strncmp(secname, "xdp/", 4) == 0)) {
            entry = f;
            break;
        }
    }

    elf_end(elf);
    close(fd);
    return entry;
}

struct marlin_chain {
    long sum;
    int path[MARLIN_MAX_FUNCS];
    int len;
};

static long round_up_stack(long v, long mult)
{
    return ((v + mult - 1) / mult) * mult;
}

static void walk_worst_chain(int idx, long round_mult, long acc, int *path, int depth, int *on_stack, struct marlin_chain *best)
{
    int has_callee = 0;

    if(on_stack[idx]) {
        fprintf(stderr, "verifier-stats: %s is on a call cycle -- BPF forbids recursion, "
                        "the call graph reconstruction is wrong\n",
                g_funcs[idx].name);
        return;
    }

    on_stack[idx] = 1;
    path[depth] = idx;
    depth++;
    acc += round_up_stack(g_funcs[idx].stack_depth, round_mult);

    for(int e = 0; e < g_nedges; e++) {
        if(g_edges[e].caller != idx) {
            continue;
        }

        has_callee = 1;
        walk_worst_chain(g_edges[e].callee, round_mult, acc, path, depth, on_stack, best);
    }

    /*
     * Every per-frame contribution is >= 0, so a path can never sum to
     * more than one of its own root-to-leaf extensions: checking leaves
     * alone is enough to find the worst chain.
     */
    if(!has_callee && acc > best->sum) {
        best->sum = acc;
        memcpy(best->path, path, sizeof(int) * (size_t)depth);
        best->len = depth;
    }

    on_stack[idx] = 0;
}

static void print_chain(const char *label, long round_mult, const struct marlin_chain *chain)
{
    printf("%s: ", label);

    for(int i = 0; i < chain->len; i++) {
        long raw = g_funcs[chain->path[i]].stack_depth;

        if(i != 0) {
            printf(" -> ");
        }

        printf("%s(%ld->%ld)", g_funcs[chain->path[i]].name, raw, round_up_stack(raw, round_mult));
    }

    printf(" = %ld / %d bytes (%.1f%% of budget)\n", chain->sum, MARLIN_MAX_BPF_STACK,
           100.0 * (double)chain->sum / MARLIN_MAX_BPF_STACK);

    if(chain->sum > MARLIN_MAX_BPF_STACK) {
        fprintf(stderr,
                "verifier-stats: %s exceeds MAX_BPF_STACK %d -- contradicts a successful "
                "load, investigate before trusting this figure\n",
                label, MARLIN_MAX_BPF_STACK);
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    char *log_buf;
    long insns;
    LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_level = 1 | 4);

    if(argc != 2) {
        fprintf(stderr, "usage: %s <marlin.bpf.o>\n", argv[0]);
        return 1;
    }

    if(build_call_graph(argv[1]) != 0) {
        fprintf(stderr, "verifier-stats: could not reconstruct the call graph from %s\n", argv[1]);
        return 1;
    }

    {
        int entry = find_entry_func(argv[1]);

        if(entry < 0) {
            fprintf(stderr, "verifier-stats: no \"xdp\" (or \"xdp/...\") section found -- "
                            "cannot compute the worst call chain\n");
        } else {
            struct marlin_chain best16;
            struct marlin_chain best32;
            int path[MARLIN_MAX_FUNCS];
            int on_stack[MARLIN_MAX_FUNCS];

            memset(&best16, 0, sizeof(best16));
            memset(&best32, 0, sizeof(best32));
            memset(on_stack, 0, sizeof(on_stack));
            walk_worst_chain(entry, 16, 0, path, 0, on_stack, &best16);
            memset(on_stack, 0, sizeof(on_stack));
            walk_worst_chain(entry, 32, 0, path, 0, on_stack, &best32);

            printf("Worst call chain, root to leaf, from the reconstructed call graph:\n");
            print_chain("  16-byte rounding (jit_enable=1, the default)", 16, &best16);
            print_chain("  32-byte rounding (jit_enable=0)              ", 32, &best32);
            printf("\n");
        }
    }

    log_buf = malloc(LOG_BUF_SIZE);
    if(log_buf == NULL) {
        fprintf(stderr, "verifier-stats: out of memory\n");
        return 1;
    }

    log_buf[0] = '\0';
    opts.kernel_log_buf = log_buf;
    opts.kernel_log_size = LOG_BUF_SIZE;

    libbpf_set_print(print_diagnostics);

    obj = bpf_object__open_file(argv[1], &opts);
    if(obj == NULL) {
        fprintf(stderr, "verifier-stats: failed to open %s\n", argv[1]);
        free(log_buf);
        return 1;
    }

    if(bpf_object__load(obj) != 0) {
        fprintf(stderr, "verifier-stats: failed to load %s\n---- verifier log ----\n%s\n", argv[1], log_buf);
        bpf_object__close(obj);
        free(log_buf);
        return 1;
    }

    insns = parse_processed_insns(log_buf);
    report_stack_depth(log_buf);

    if(insns >= 0) {
        printf("\nProcessed instructions: %ld / %d (%.1f%% of budget)\n", insns, MARLIN_VERIFIER_INSN_LIMIT,
               100.0 * (double)insns / MARLIN_VERIFIER_INSN_LIMIT);
    } else {
        printf("\nProcessed instructions: not found in the verifier log\n");
    }

    bpf_object__close(obj);
    free(log_buf);
    return 0;
}
