# Packed 64-slot sent-packet blocks with direct successor lookup

**AI disclosure:** OpenAI Codex implemented the experiments, ran these measurements on the owner's Fedora laptop, and prepared this report. The owner requested publication in this draft PR for review.

This experimental alternative to [quinn-rs/quinn#2858](https://github.com/quinn-rs/quinn/pull/2858) stores sent packets in blocks of at most 64 slots. Directly accessible head/tail blocks use `VecDeque`; a BTreeMap directory indexes boxed intermediate blocks. Packet-number gaps never allocate padding, and each compaction is local to one block. Edge promotion may convert one additional block. No operation compacts the entire packet window.

Boxed intermediate blocks shrink to their live entries at half occupancy. This removed the earlier block queue's roughly 65% memory overhead in the constructed fragmented case. The current version also specializes the single-successor query used to limit retained non-ACK-eliciting packets. It remains more complex than BTreeMap and is a draft for design review, not a claim that every workload improves.

The published packed queue spends unnecessary time constructing a general range iterator when `PacketSpace::sent` only wants the first live packet after a packet number. The final candidate introduces `SentPackets::first_after(pn)` and uses it at that actual call site. It reduces the original two-survivor successor operation by **71.1% versus the published packed queue** in the final matched series. BTreeMap remains a useful reference; this is not a claim of superiority for every operation.

## Code change

- Search the directly accessible head block first, starting at the lower bound of `pn` and skipping the equal key and tombstones. Searching for `pn + 1` would miss the existing-key shortcut across large gaps.
- If the query is already in the tail's key interval, search that block directly without a directory lookup.
- Otherwise, search the middle directory for the containing block. A hit there needs one tree lookup; only an exhausted candidate requires a second lookup for the next block.
- Keep the existing general `range()` implementation for actual range iteration. No cache, stored index, allocation, storage representation or insertion/removal algorithm is added or changed.

Production changes are in [`sent_packets.rs`](../../quinn-proto/src/connection/sent_packets.rs) and its caller in [`spaces.rs`](../../quinn-proto/src/connection/spaces.rs). The published packed reference is commit `b7839fd60512079e9207b9867666ad3fa24db533`; its packet storage is preserved in [packed-reference.rs](packed-reference.rs). BTreeMap is pinned to `d11d61556d41395aedbde7ff52e0b9e1af25aa42` from upstream PR #2858. The PR keeps implementation/regression tests and benchmark/report changes in two logical commits.

**Benchmark API change:** The successor workloads call `range((Excluded(pn), Unbounded)).next()` on the references and `first_after(pn)` on the candidate. They request the same result. The real `PacketSpace::sent` call site is changed in the candidate too. The old general range API itself has not become an 8 ns operation. Short and complete range scans retain exactly the same API for all implementations.

## Final measurements

This final series contains **258 successful processes**: 90 original microbenchmark processes, 126 additional range-position processes, 36 encrypted transfers, and six cleanup/memory processes. Earlier studies in the [packed report](PACKED-REPORT.md), [block report](BLOCKS-REPORT.md), and [single-queue report](TRIM-REPORT.md) are retained separately and are not pooled into the numbers below.

All six orders of BTreeMap (`pr`), published packed (`packed`) and the candidate (`successor-final`) were used once per microbenchmark and twice for transfers. Order was shuffled with seed 285806. Microbenchmarks ran on CPU 4 for at least 0.6 s each. Transfers used separate optimized executables, IPv4 loopback, one stream, 64 MiB, client/server CPUs 0/2, one second warmup, at least three seconds measurement, and two seconds pause between processes. Socket buffers requested 4 MiB. All 36 transfers passed completion/byte-count checks and reported zero loss.

AC and the performance profile were checked at roughly 100 ms intervals, with raw guard samples retained. The user had closed interactive Firefox; the idle Fedora D-Bus activation service remained. This runner does not claim to have continuously monitored Firefox absence. No builds or test suites ran during the final timing phases.

Fedora 44, Intel Core Ultra 7 155U, Rust 1.98.1 / LLVM 22.1.8; kernel `7.3.0-rc2.vanilla.fc44.20260908221956518389`. Recorded temperatures ranged from 91 to 102 °C across phases. Dynamic frequency, desktop activity and non-exclusive CPU affinity remain limitations.

### Successor queries

Median ns per query. The original `successor_65536` case contains **two live entries** separated by a 65,536-number gap; it is not a 65,536-live-entry search. The additional dense position cases contain 65,536 entries; the fragmented case retains one entry per block.

| Query | BTreeMap | Published packed | Direct successor |
|---|---:|---:|---:|
| Original two-survivor gap | 11.13 | 31.35 | **8.46** |
| Dense head | 28.26 | 70.87 | **10.78** |
| Dense middle | 40.81 | 86.20 | **27.87** |
| Dense tail | 47.17 | 81.67 | **16.97** |
| Beyond the last packet | 49.02 | 84.15 | **16.36** |
| Fragmented middle | 26.49 | 82.86 | 27.76 |

For the original gap case, matched query-time changes are **−71.1% [−72.8%, −69.5%]** versus published packed and **−21.9% [−24.9%, −17.9%]** versus BTreeMap. The fragmented-middle query is **+4.0% [−5.8%, +15.0%]** versus BTreeMap, so no clear difference is established there. The candidate is substantially faster than published packed in all six measured successor cases.

Ratios are geometric means of the six per-round matched ratios; brackets are descriptive 95% percentile bootstrap intervals from 10,000 resamples. They are not ratios of the displayed medians. Inner iterations are not independent replicates, and there is no multiple-comparison correction. The cases use repeated fixed probes on warm data, not randomized production query traces; they do not exhaust all gap/tombstone patterns.

### General operations and remaining regression

The four existing dense/random/selective packet-management cases show no clear candidate-versus-packed difference in this final series. Median ns per harness operation:

| Case | BTreeMap | Published packed | Candidate |
|---|---:|---:|---:|
| `dense_1024_32_meta` | 155.53 | 87.91 | 83.57 |
| `dense_16384_32` | 206.17 | 94.95 | 90.66 |
| `random_16384` | 443.23 | 248.15 | 234.32 |
| `selective_16384` | 254.26 | 111.93 | 112.80 |

The additional 32-entry `short_head` range scan regressed: **89.37 ns versus 80.29 ns** for published packed, matched **+10.5% [+6.1%, +15.0%]**. Its general range implementation is unchanged, so the result cannot be attributed to a changed range algorithm. Compiler/code-layout and session effects are possible explanations, not established causes. The measured regression is retained rather than dismissed.

A full 65,536-entry scan measured 158.52 µs versus 155.19 µs for packed; the paired difference was +1.5% [−0.8%, +3.9%]. Thus this follow-up does not demonstrate that every operation improves or that all regressions have been eliminated.

### Encrypted transfer

Twelve matched triplets, separate from the microbenchmarks:

| Comparison | Throughput change | CPU time per byte change |
|---|---:|---:|
| Candidate / BTreeMap | **+4.5% [+2.1%, +6.6%]** | **−4.0% [−5.9%, −2.1%]** |
| Candidate / published packed | −1.0% [−4.1%, +1.7%] | +1.1% [−1.2%, +3.4%] |

No clear transfer-throughput difference versus published packed is established. This is not an equivalence or non-inferiority result: a modest regression remains possible. The large microbenchmark gain is not a claim that all packets or application transfers become proportionally faster; the changed call site handles limiting the retained non-ACK-eliciting tail.

### Memory and cleanup

The fresh-process fragmented case (one survivor per 64-slot block, 1,024 live packets) retained **182,976 bytes for both packed variants**, versus 198,528 for BTreeMap. These are glibc allocator deltas (`uordblks + hblkhd`), not RSS or full connection memory. No additional storage fields are introduced by this patch.

Across the same 18 constructed cleanup cases, each with 32 samples, the largest candidate operation was **1.377 µs**, versus 1.872 µs for the published packed reference in this run. The candidate's actual half-occupancy compaction at a 65,536-entry window had a 0.743 µs median and 1.047 µs maximum. The block-size bound and compaction mechanism are unchanged. These process-order-dependent operation samples are not network p99 measurements or hard latency bounds.

## Validation and artifacts

The clean review checkout passed **359 unit/integration tests and four doc-tests**, with four pre-existing tests ignored, using `cargo test --release --locked -p quinn-proto -p quinn -p quinn-udp`. `cargo fmt --all -- --check` and `cargo clippy --locked --all-targets -- -D warnings` passed. The new regression test compares every probe in a bounded range, plus `u64::MAX - 1` and `u64::MAX`, against BTreeMap through insertion, fragmented deletion, head promotion and exhaustion.

The reviewed source was verified against rustfmt output of the measured source, including its removal of redundant closure braces. Original binaries are preserved. Each variant used a separate target directory, and benchmark binaries were copied before later probe builds.

- [Original-case raw observations](results/successor-final-micro-results.jsonl) and [summary](results/successor-final-micro-summary.json).
- [Additional range-position observations](results/successor-final-positions-results.jsonl) and [summary](results/successor-final-positions-summary.json).
- [Encrypted-transfer observations](results/successor-final-transfer-results.jsonl) and [summary](results/successor-final-transfer-summary.json).
- [Cleanup/memory observations](results/successor-final-cleanup-results.jsonl) and [summary](results/successor-final-cleanup-summary.json).
- [Original source/executable/data hashes and environment ranges](results/successor-final-manifest.json); paths in this manifest identify the original benchmark workspace.
- [Builder](build.py), [runner and replay analysis](run-successor.py), [original microbenchmark/cleanup harness](micro.rs), [additional range probes](range-positions.rs), and [encrypted-transfer harness](e2e.rs).
- [Clippy log](results/successor-review-clippy.log) and [test log](results/successor-review-suite.log).

## Reproduction

From this directory in a fresh Git checkout of the draft:

```sh
python3 build.py --variants pr packed successor-final
python3 run-successor.py micro
python3 run-successor.py positions
python3 run-successor.py transfer
python3 run-successor.py cleanup
```

The builder creates detached worktrees at the pinned BTreeMap base and isolated Cargo target directories under ignored `local/`. It substitutes the preserved packed reference or the current candidate's two production files. All variants share the harness; only the successor query is adapted to `first_after()` for the candidate. General range scans retain the same API. Separate probe binaries include the additional position workloads; the ordinary microbenchmark binary is preserved before those builds. Existing worktrees and observations are not overwritten.

The default `build.py` variants (`pr blocks packed`) still support the historical `run.py`/`run-cleanup.py`/`run-control.py` workflows. `--prepare-only` uses ignored `successor-prepare-check/`. The scripts assume Linux/glibc and this laptop's CPU/sysfs layout; adapt these for another machine.

To replay a saved phase without measuring, place its raw JSONL under `local/artifacts/` and run `python3 run-successor.py <phase> --analyze-only`. The packaged analysis validates counts, uniqueness, AC/profile guards and transfer loss before writing the summary. Packaging was checked by preparing all three current variants and replaying all four saved phases byte-for-byte; a complete fresh build/measurement cycle through this repackaged builder was not repeated.

## CI environment and inherited dependency findings

Earlier CI runs flagged inherited `rustls` 0.23.43 (RUSTSEC-2026-0285, recommendation >=0.23.45). Android setup also failed because `sdkmanager` could not find the `tools` package, before compilation. Dependency manifests, Cargo.lock and CI workflows are unchanged from the pinned base. This draft does not suppress those checks or add unrelated dependency/runner updates.

The original two-survivor successor penalty is substantially addressed at the actual caller, without changing storage or cleanup. The remaining short-range regression and uncertain small transfer difference should remain visible in review before claiming an across-the-board improvement.
