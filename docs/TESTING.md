# Marlin — Testing in WSL2

This document explains how developers set up an isolated test environment in WSL2 to test the Marlin BPF datapath without affecting production network interfaces.

For the overall test strategy, see `docs/design/24-testing.md`. For packet-level unit tests using `bpf_prog_test_run`, see `data-plane/tests/packet/` (§5.2 below).

**WSL2 advantage:** You can create virtual test interfaces, load the XDP program onto them, and exercise them without touching the host's actual network adapters.

Development tools (clang, llvm, bpftool) are set up in `CONTRIBUTING.md`.

---

## 1. Setting Up a Test Interface

A test interface is an isolated virtual network device that you can attach the BPF program to without affecting your WSL2 host's routing or real network.

### 1.1 Using a veth pair (recommended)

A veth pair creates two virtual Ethernet devices connected to each other. Attach the BPF program to one side and send test traffic in on the other.

```bash
# Create a veth pair: veth_test0 ↔ veth_peer0
ip link add veth_test0 type veth peer name veth_peer0

# Bring both ends up
ip link set veth_test0 up
ip link set veth_peer0 up

# Give them IP addresses for testing
ip addr add 198.51.100.10/24 dev veth_test0
ip addr add 198.51.100.20/24 dev veth_peer0
```

You will attach the BPF program to `veth_test0` and send test packets in via `veth_peer0`.

**Verify the setup:**

```bash
ip link show veth_test0
ip addr show veth_test0
```

### 1.2 Using a dummy interface (simpler alternative)

If you only need an interface to attach to (not bidirectional testing):

```bash
ip link add dummy_test type dummy
ip link set dummy_test up
ip addr add 198.51.100.10/32 dev dummy_test
```

---

## 2. Building the BPF Object

From the repository root:

```bash
cd data-plane
make clean
make
```

This produces `data-plane/marlin.bpf.o` containing the compiled BPF bytecode with embedded BTF.

**Verify the build:**

```bash
file data-plane/marlin.bpf.o
bpftool prog load data-plane/marlin.bpf.o type xdp
```

---

## 3. Setting Up the BPF Filesystem

Programs and maps must be pinned under the BPF filesystem. Mount it if not already mounted:

```bash
mount | grep bpf
# If no output, mount it:
sudo mount -t bpf bpf /sys/fs/bpf
```

Create the pin directory:

```bash
sudo mkdir -p /sys/fs/bpf/marlin
```

---

## 4. Loading and Attaching the BPF Program

### 4.1 Load the program and pin maps

```bash
sudo bpftool prog loadall data-plane/marlin.bpf.o /sys/fs/bpf/marlin \
    pinmaps /sys/fs/bpf/marlin
```

**What this does:**
- Loads every program in the object file
- Pins all maps under `/sys/fs/bpf/marlin/<map_name>`
- Maps are sized at compile time; no pre-creation needed

**Verify:**

```bash
bpftool prog list
bpftool map list
bpftool prog show pinned /sys/fs/bpf/marlin/xdp_marlin
```

### 4.2 Attach to the test interface

```bash
# Attach to veth_test0 (or your test interface name)
sudo bpftool net attach xdpdrv pinned /sys/fs/bpf/marlin/xdp_marlin dev veth_test0
```

**Verify attachment:**

```bash
bpftool net list
ip link show veth_test0  # should show "xdp" in the output
```

**Detaching** (later, when done testing):

```bash
sudo ip link set dev veth_test0 xdp off
# or
sudo bpftool net detach xdpdrv dev veth_test0
```

---

## 5. Sending Test Packets

### 5.1 Using packet crafting tools

Send packets in on the peer side of the veth pair:

```bash
# Send a simple IPv4 packet to veth_peer0
# (assumes you've configured a VIP and backend in the maps first)
tcpdump -i veth_peer0 -n -l &
sudo scapy  # Python packet library, or use a custom tool
```

Or use `scapy` in Python:

```python
from scapy.all import *

# Create a simple packet
pkt = IP(dst="203.0.113.10") / TCP(dport=80)

# Send it in on veth_peer0
sendp(pkt, iface="veth_peer0")
```

### 5.2 Using bpf_prog_test_run (unit testing)

For deterministic testing without needing a full network, use the packet harness in
`data-plane/tests/packet/` (`docs/REPO-STRUCTURE.md` §7.2 settled this at `data-plane/tests/packet/`,
C + libbpf, rather than the repo-root `tests/packet/` this section used to describe). It loads
the real `marlin.bpf.o` and runs it through `bpf_prog_test_run`, so it needs root or
`CAP_BPF`+`CAP_NET_ADMIN`+`CAP_PERFMON` to load the program -- not a live network interface:

```bash
cd data-plane
sudo make packet-tests
```

See `docs/design/24-testing.md` for coverage details. This is the primary test path and is
phase-gated: coverage is bounded by what `xdp_main` can satisfy, and an assertion whose path it
cannot reach reports as a named `skip` (`data-plane/tests/packet/xdp_*.c`). `nexthop.c`'s
`bpf_fib_lookup()` matrix needs no VIP lookup at all -- `data-plane/tests/packet/fib.h`/`fib.c` build
a veth topology with real routes and neighbours inside the same unshared network namespace.

### 5.3 Using the native unit tests

Narrower than 5.2 and already in the tree: `data-plane/tests/` compiles a `bpf/*.c` file with the
host toolchain and calls its helpers directly, with no BPF object and no interface. `parser.c`
reads no map at all; `acl.c` reads four through `data-plane/tests/stubs/`, which shadows libbpf's
`<bpf/bpf_helpers.h>` with a host longest-prefix scan; `ipip.c` calls the one helper it needs,
`bpf_xdp_adjust_head()`, through the same shadowed header, answered by
`data-plane/tests/stubs/xdp_stub.h` (`docs/design/24-testing.md`, "Native unit tests"). Runs in
milliseconds, one binary per test file:

```bash
cd data-plane
make tests
```

Not part of `make all`; part of `make ci`. Use it to check a `parser.c`, `acl.c` or `ipip.c`
change before reaching for 5.2's packet harness.

---

## 6. Reading Counters and Statistics

Marlin writes counters to three maps: `drop_stats`, `vip_stats`, and `backend_stats`. Query them while forwarding happens.

### 6.1 List all maps

```bash
bpftool map list
```

Find the map IDs for `drop_stats`, `vip_stats`, `backend_stats`, etc.

### 6.2 Dump drop statistics

`drop_stats` is keyed by drop reason (index). The keys and reasons are listed in `docs/design/22-observability.md`:

```bash
# Dump the entire map (once you've sent test packets)
bpftool map dump name drop_stats
```

Interpret the output using the enumeration in `marlin.h:enum marlin_ret` and `docs/design/22-observability.md`.

### 6.3 Dump VIP and backend statistics

```bash
# VIP statistics (keyed by VIP number)
bpftool map dump name vip_stats

# Backend statistics (keyed by backend ID)
bpftool map dump name backend_stats
```

The keys and values are defined in `data-plane/include/marlin/abi/types.h`.

### 6.4 Inspect map contents

View the current configuration written by the control plane:

```bash
# View the forwarding table
bpftool map dump name fwd_table | head -20

# View backends
bpftool map dump name backends

# View VIPs
bpftool map dump name vip_map
```

---

## 7. Debugging the BPF Program

### 7.1 Using bpf_printk (print debugging)

The datapath can emit debug output with `bpf_printk`:

```c
// In C code:
#define bpf_printk(fmt, ...)                                          \
({                                                                     \
    char ____fmt[] = fmt;                                              \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);        \
})

// In your code:
bpf_printk("Packet: src=%x, dst=%x", src_ip, dst_ip);
```

Read output from the kernel trace buffer:

```bash
# In one terminal, tail the trace:
sudo cat /sys/kernel/debug/tracing/trace_pipe

# In another, send packets (step §5.1)
```

Every `bpf_printk` appears in the trace buffer in real time.

**Note:** `bpf_printk` is a development aid only. Remove it before production; it has non-trivial overhead.

### 7.2 Using perf for XDP tracing

Trace XDP program execution with `perf`:

```bash
# Record XDP events while you send traffic
sudo perf record -e xdp:xdp_exception --sample-cpu -g -c 1000 &

# Send test packets here (step §5.1)

# Stop recording (Ctrl+C)

# View the report
sudo perf report
```

This captures exceptions and program flow for high-level profiling.

### 7.3 Using bpftrace for dynamic tracing

`bpftrace` lets you write dynamic probes on BPF program execution. See the bpftrace documentation for usage examples and syntax.

Example: trace every XDP return value:

```bash
sudo bpftrace -e 'tracepoint:xdp:xdp_exception { printf("exception: %s\n", args->name); }'
```

### 7.4 Reading the verifier output

The BPF verifier analyzes your code at load time. Check its output for warnings or issues:

```bash
# Verbose load to see verifier feedback
bpftool prog load data-plane/marlin.bpf.o /tmp/test_prog type xdp \
    verbose

# Check verifier complexity (recorded in CI)
bpftool prog show id <ID> stats
```

---

## 8. A Complete Test Session Example

Here's a start-to-finish example:

```bash
#!/bin/bash
set -e

# 1. Clean up any old setup
sudo ip link del veth_test0 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/marlin

# 2. Create test interface
sudo ip link add veth_test0 type veth peer name veth_peer0
sudo ip link set veth_test0 up
sudo ip link set veth_peer0 up

# 3. Ensure BPF filesystem is mounted
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
sudo mkdir -p /sys/fs/bpf/marlin

# 4. Build the datapath
cd data-plane && make && cd ..

# 5. Load and attach
sudo bpftool prog loadall data-plane/marlin.bpf.o /sys/fs/bpf/marlin \
    pinmaps /sys/fs/bpf/marlin

sudo bpftool net attach xdpdrv pinned /sys/fs/bpf/marlin/xdp_marlin \
    dev veth_test0

echo "✓ BPF program loaded and attached to veth_test0"

# 6. In another terminal: tail the trace
# sudo cat /sys/kernel/debug/tracing/trace_pipe

# 7. Configure the control plane (or manually write maps)
# This is where the C# service would populate vip_map, backends, etc.
# For manual testing, you can use bpftool:
# sudo bpftool map update name vip_map key ... value ...

# 8. Send test traffic in on the peer
# (step §5.1 — tcpdump, scapy, or a custom tool)

# 9. Check the results
echo ""
echo "Drop statistics:"
bpftool map dump name drop_stats

echo ""
echo "VIP statistics:"
bpftool map dump name vip_stats

# 10. Clean up
echo ""
echo "Cleaning up..."
sudo ip link set dev veth_test0 xdp off
sudo ip link del veth_test0
```

---

## 9. Common Issues

| Problem | Cause | Solution |
|---|---|---|
| "prog loadall: cannot open object" | Wrong path to `marlin.bpf.o` | Check `pwd` and file exists: `ls -la data-plane/marlin.bpf.o` |
| "xdpdrv not supported" | Device doesn't support native XDP | Try with `xdpgeneric`, or test interface must support XDP — in WSL2, veth and dummy typically support it |
| "Permission denied" | Not running as root | Prefix with `sudo` |
| No output from `bpf_printk` | Trace buffer not being read | Ensure `/sys/kernel/debug/tracing/` is mounted; check `cat /sys/kernel/debug/tracing/trace_pipe` |
| Maps show zero counters | Program not being invoked | Verify interface is attached (`bpftool net list`), packets are actually arriving |

---

## 10. Integrating with the C# Control Plane (Future)

In Phase 1, the control plane is minimal and maps are written manually. As the control plane grows, it will:

1. Open pinned map paths (no creation)
2. Write VIP, backend and configuration entries
3. Read statistics in a loop

For now, development testing uses `bpf_prog_test_run` (§5.2) or manual map writes. Once the control plane is in place, replace manual writes with calls to the C# service on your test host.

---

## 11. References

- **Unit testing:** `docs/design/24-testing.md`
- **Counters and observability:** `docs/design/22-observability.md`
- **Map ABI:** `data-plane/include/marlin/abi/types.h`
- **Deployment (production):** `DEPLOYMENT.md`
- **Repository layout:** `REPO-STRUCTURE.md`

---

## 12. Next Steps

1. **Run the packet tests:** `cd data-plane && sudo make packet-tests`
2. **Inspect the datapath code:** `data-plane/bpf/marlin.c` and callees
3. **Read the design:** `docs/design/README.md` for the forwarding pipeline
4. **Set up continuous monitoring:** Background a `trace_pipe` tail and watch real-time trace output while forwarding
