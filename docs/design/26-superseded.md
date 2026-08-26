# Marlin — Superseded During Design

## Superseded during design

Recorded so they are not re-proposed on the strength of an earlier argument.

**"Fixed backend set with up/down flags makes all transitions zero-disruption."** Partly wrong.
It holds for failure and recovery — which the state flag already covers, changing no rows at
all. It does not hold for capacity growth: rows reserved for a backend that does not exist yet
either drop their share of traffic or require a fallthrough whose connections break when the
real backend arrives. Corrected in `docs/design/17-reconfiguration.md`.

**"NAT conntrack machinery makes a flow cache nearly free."** Overstated, and moot now.
Shared: the flow key struct and the lookup-then-fallback control flow. Not shared: map type,
miss semantics, the reverse map, port allocation, expiry.

**"Global subprograms accept only scalars and `PTR_TO_CTX`."** Out of date. True before 5.13,
which added struct pointer arguments — so the output-parameter convention is available at
Marlin's 6.0 floor. The scalar-only restriction applies to *return* values, on all versions.

**"Weights are expressed by repeating a backend across more rows."** Wrong. Row repetition is
not weighted rendezvous; it breaks the per-row ordering invariant and with it the removal
guarantee in `docs/design/17-reconfiguration.md`. Corrected to a weighted score in `docs/design/12-selection.md`.

**"Source-address hashing steers ICMP errors correctly."** Wrong. An ICMP error's source is the
router that generated it. Correct steering requires parsing the embedded header — and hashing
its *destination*, since the embedded packet travelled backend→client. Corrected in `docs/design/13-icmp.md`.

**"The DSR datapath is three reads and no writes."** Wrong once statistics are mandatory. The
property that holds is no per-flow state and deterministic output. Corrected in `docs/design/22-observability.md` and `docs/design/24-testing.md`.

**"The BPF stack limit is 512 bytes per frame."** Wrong: 512 bytes is the combined depth across
the whole call chain. Corrected in `docs/design/05-budgets.md`, with a stated `marlin_ctx` budget.

**"The ICMP branch replaces steps 2 and 3 of the pipeline."** Wrong once `parse.c` normalised
both orientations. Step 3 is the VIP lookup, and normalisation exists so that the lookup is
*not* branched. The branch replaces step 2 only. Corrected in `docs/design/13-icmp.md`.

**"C# map structs are generated from the compiled BTF as a build step."** Superseded, on
feasibility. `bpftool btf dump` emits raw, JSON or C — never C# — and no BTF-to-C# generator
exists, so the step named a source and a prohibition but no mechanism. Writing one was rejected
against the size of the struct set. Both sides are hand-written and the mismatch risk is
accepted; corrected in `docs/design/06-map-abi.md`.

**"Health probes are encapsulated to the backend's own address."** Superseded. It avoids the
martian reply but gives up detection of the one failure L2 DSR can have. Probes are addressed to
the VIP from a VRF that does not hold it. Corrected in `docs/design/18-health.md`.
