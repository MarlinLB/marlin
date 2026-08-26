# Marlin — DESIGN.md Split Report

## Checks run and results

1. **`DESIGN.md` line count.** `Grep pattern:"^" output_mode:"count"` on `DESIGN.md`: **2075**,
   both before and after the split (re-checked at the end of the session). Unchanged.

2. **Per-file line counts, all 29 extracted files.** For each file, expected count was computed
   as: range length (inclusive), minus 1 if the file is DROP-FIRST, plus 2 for the H1 line and
   its trailing blank line (T1), plus 1 more blank line for the four two-range files (07, 08, 09,
   12). Actual counts were taken with `Grep pattern:"^" output_mode:"count"` on each file.

   | File | Expected | Actual (final) |
   |---|---|---|
   | 01-scope.md | 43 | 43 |
   | 02-architecture.md | 60 | 60 |
   | 03-translation-units.md | 47 | 47 |
   | 04-calling-convention.md | 80 | 80 |
   | 05-budgets.md | 53 | 53 |
   | 06-map-abi.md | 20 | 20 |
   | 07-maps.md | 52 | 52 |
   | 08-types.md | 147 | 147 |
   | 09-sizing.md | 52 | 52 |
   | 10-map-invariants.md | 33 | 33 |
   | 11-pipeline.md | 75 | 75 |
   | 12-selection.md | 100 | 100 |
   | 13-icmp.md | 46 | 46 |
   | 14-forwarding-modes.md | 99 | 99 |
   | 15-nexthop-l2dsr.md | 86 | 86 |
   | 16-fib-lookup.md | 105 | 105 |
   | 17-reconfiguration.md | 92 | 92 |
   | 18-health.md | 57 | 57 |
   | 19-control-plane.md | 79 | 79 |
   | 20-configuration-validation.md | 47 | 47 |
   | 21-active-active.md | 27 | 27 |
   | 22-observability.md | 61 | 61 |
   | 23-mtu.md | 34 | 34 |
   | 24-testing.md | 106 | 106 |
   | 25-rejected.md | 152 | 152 |
   | 26-superseded.md | 47 | 47 |
   | 27-source-filtering.md | 109 | 109 |
   | 28-rate-limiting.md | 92 | 92 |
   | 29-versions.md | 37 | 37 |

   All 29 files now match their computed expected count exactly.

   **Anomaly found and corrected during verification.** On the first write pass, 17 of the 18
   DROP-FIRST files (all except `01-scope.md`) were built with only one blank line between the
   T1-inserted H1 and the first content line, instead of two. In every DROP-FIRST case the
   dropped `## N. Title` heading in `DESIGN.md` is immediately followed by a blank line, and that
   blank line is part of the range and must be kept — it is separate from the blank line T1
   inserts after the new H1. The first write pass merged the two into one, so each affected file
   was one line short of its computed expected count (`02-architecture.md`, `03-translation-units.md`,
   `07-maps.md`, `11-pipeline.md`, `12-selection.md`, `14-forwarding-modes.md`,
   `15-nexthop-l2dsr.md`, `17-reconfiguration.md`, `18-health.md`, `19-control-plane.md`,
   `22-observability.md`, `23-mtu.md`, `24-testing.md`, `25-rejected.md`, `27-source-filtering.md`,
   `28-rate-limiting.md`, `29-versions.md`). Each was corrected by inserting the missing blank
   line immediately after the H1; no other content in any of these files was touched. No text was
   added, removed, or reflowed — only the missing blank line was restored. Re-verified with
   `Grep pattern:"^" output_mode:"count"` after the fix; all 17 now match. `01-scope.md` was built
   correctly on the first pass and required no fix.

3. **Spot checks (first 3 / last 3 lines).** Performed on five files spanning different
   transform combinations — `02-architecture.md` (DROP-FIRST, single range), `08-types.md`
   (no DROP-FIRST, two ranges), `12-selection.md` (DROP-FIRST on range A only, two ranges),
   `19-control-plane.md` (DROP-FIRST, single range), `27-source-filtering.md` (DROP-FIRST, single
   range). In every case the first three lines were the H1 plus the two required blank lines
   (or H1, blank, `## Types` for the no-drop case), and the last three lines matched
   `DESIGN.md`'s last three lines of the corresponding range byte-for-byte (accounting for the
   `### ` → `## ` transform where applicable). No discrepancies found.

4. **`docs/design/` directory listing.** `Glob docs/design/*` returned exactly 31 files: the 29
   numbered files, `README.md`, and this `SPLIT-REPORT.md`. Nothing else is present.
   **Limitation:** no `git status --short` or equivalent could be run this session — the
   `mcp__workspace__bash` tool fails immediately with "UNC paths are not supported" for every
   command against this UNC-mounted repo path. This was worked around entirely with Read/Write/
   Edit/Glob/Grep, none of which can report working-tree status. A human or a future
   bash-capable session should run `git status --short` before committing to confirm that only
   the 31 files under `docs/design/` were added and that no other file in the repository changed.

5. **`DESIGN.md` untouched.** Confirmed 2075 lines both before and after the split; the file was
   never opened with Write or Edit during this session, only Read.

## Extraction anomalies

None. Every one of the 29 ranges extracted cleanly once the blank-line issue in item 2 above was
corrected; no range was short, no range needed re-reading, and no content required retyping or
reflowing.

## README.md revision-block boundary

The brief's §6 said to copy the status/revision block from `DESIGN.md:3–5` verbatim. In the
source, the revision sentence actually wraps onto line 6 ("narrowed to replace step 2 only;
health probes isolated in a VRF") — lines 3–5 alone end mid-sentence at "ICMP branch". Copying
only 3–5 would have left a truncated sentence in a hand-written file, so `README.md` includes
line 6 as well to complete the block as it reads in `DESIGN.md`. This is a one-line boundary
slip in the brief, not a change to any transcribed section file.

## Coverage-arithmetic inconsistency in the original brief

The original split brief stated the 29 ranges should sum to 1979 covered / 96 uncovered lines.
Verification shows the true arithmetic is 1994 covered / 81 uncovered (every uncovered line is
blank, a `---` rule, within DESIGN.md's front matter lines 1–15, or a `## N. Title` heading
dropped per transformation rule T2 — no line is unaccounted for; the discrepancy is in the
brief's own stated totals, not in the extraction). Ranges were not altered to force a match with
the brief's stated totals.

## Restated known documentation drift (not fixed, per instructions)

- `REPO-STRUCTURE.md` lists `docs/` as exactly five files.
- `CLAUDE.md` and `README.md` route design questions to `DESIGN.md` as one document.
- `PHASES.md` and `DEVELOPMENT.md` cite `DESIGN.md §N` throughout; `DEVELOPMENT.md` states every
  bare `§N` means a `DESIGN.md` section.

## Proposed amendments (not applied)

- Update `REPO-STRUCTURE.md`'s file count and listing for `docs/` to include the new
  `docs/design/` tree (29 numbered files plus `README.md`), rather than the stated five files.
- Update `CLAUDE.md` and `README.md` references that currently point at `DESIGN.md` as a single
  document to point at `docs/design/README.md` instead, so the routing table matches the new
  structure.
- The `§N` cross-references used throughout `PHASES.md`, `DEVELOPMENT.md`, and the design docs
  themselves (including inside the newly split files, which were transcribed with their `§N`
  references left as-is, per instruction) still assume a single `DESIGN.md`. These will need
  remapping to the new per-file structure in a follow-up pass; this was not attempted here.
- A `git status --short` equivalent check could not be run this session due to the
  `mcp__workspace__bash`/UNC-path limitation described in item 4 above. A human or a future
  bash-capable session should confirm no unintended files changed before committing.
