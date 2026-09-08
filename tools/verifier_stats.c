/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Loads marlin.bpf.o with full verifier logging and reports the two figures
 * docs/design/05-budgets.md tracks: processed instructions against the
 * 1,000,000 verifier limit, and the worst combined stack depth against the
 * 512-byte MAX_BPF_STACK limit. Deliberately does not pin anything:
 * bpf_object__load() keeps program fds open in this process, closed on
 * exit, so nothing under /sys/fs/bpf is ever touched -- unlike `bpftool
 * prog load`/`loadall`, whose pinning step some hosts' LSM policy blocks
 * even under root.
 *
 * The kernel's "stack depth" log line lists one figure per BPF-to-BPF
 * callable function: each is that function's own worst-case depth if
 * execution starts there, not frames of one chain to add together. Marlin's
 * units are only ever called as sequential siblings from xdp_main, never
 * nested in each other, so at most one of them plus xdp_main's own frame is
 * ever on the stack at once -- summing every figure, which is the obvious
 * misreading, produces a number with no relationship to anything the
 * verifier actually enforces. This prints each figure and their max
 * explicitly rather than relaying the raw, easily-misread line.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
 * Prints each "stack depth A+B+C+..." figure on its own line and returns
 * their max -- the figure MAX_BPF_STACK is actually checked against.
 */
static long report_stack_depth(const char *log)
{
    static const char needle[] = "stack depth ";
    const char *p = strstr(log, needle);
    char *line;
    char *tok;
    char *saveptr;
    char *newline;
    long max = -1;
    long val;
    int idx = 0;

    if(p == NULL) {
        return -1;
    }

    line = strdup(p + sizeof(needle) - 1);
    if(line == NULL) {
        return -1;
    }

    newline = strchr(line, '\n');
    if(newline != NULL) {
        *newline = '\0';
    }

    printf("Per-function worst-case stack depth if execution starts there (bytes):\n");

    for(tok = strtok_r(line, "+", &saveptr); tok != NULL; tok = strtok_r(NULL, "+", &saveptr)) {
        val = strtol(tok, NULL, 10);
        printf("  function #%d: %ld\n", idx, val);

        if(val > max) {
            max = val;
        }

        idx++;
    }

    free(line);
    return max;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    char *log_buf;
    long insns;
    long stack;
    LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_level = 1 | 2 | 4);

    if(argc != 2) {
        fprintf(stderr, "usage: %s <marlin.bpf.o>\n", argv[0]);
        return 1;
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
    stack = report_stack_depth(log_buf);

    if(insns >= 0) {
        printf("\nProcessed instructions: %ld / %d (%.1f%% of budget)\n", insns, MARLIN_VERIFIER_INSN_LIMIT,
               100.0 * (double)insns / MARLIN_VERIFIER_INSN_LIMIT);
    } else {
        printf("\nProcessed instructions: not found in the verifier log\n");
    }

    if(stack >= 0) {
        printf("Worst combined stack depth: %ld / %d bytes (%.1f%% of budget) -- the MAX of the "
               "per-function figures above, not their sum.\n",
               stack, MARLIN_MAX_BPF_STACK, 100.0 * (double)stack / MARLIN_MAX_BPF_STACK);

        if(stack > MARLIN_MAX_BPF_STACK) {
            fprintf(stderr,
                    "verifier-stats: %ld exceeds MAX_BPF_STACK %d -- contradicts a successful "
                    "load, investigate before trusting this figure\n",
                    stack, MARLIN_MAX_BPF_STACK);
        }
    } else {
        printf("Worst combined stack depth: not found in the verifier log\n");
    }

    bpf_object__close(obj);
    free(log_buf);
    return 0;
}
