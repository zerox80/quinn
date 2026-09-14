> Historical report for the first block queue. Reproduction commands here apply to [commit 13fed611](https://github.com/zerox80/quinn/tree/13fed611), not the current compact-intermediate-block harness.

# Block-bounded sent-packet queue: experimental review

**AI disclosure:** OpenAI Codex implemented these prototypes and harnesses, executed the measurements on the owner's Fedora laptop, and prepared this report. The owner requested that the work be published for review.

This draft explores an alternative to the BTreeMap implementation in [quinn-rs/quinn#2858](https://github.com/quinn-rs/quinn/pull/2858), at exact head `d11d61556d41395aedbde7ff52e0b9e1af25aa42`. It addresses both packet-number-span-dependent storage and the large compaction pauses observed in the earlier single-queue prototype. It remains experimental.

## Representation and cleanup bound

Packets are stored in sorted blocks of at most **64 slots**. The oldest and newest blocks are directly accessible, while a `BTreeMap` indexes the intermediate blocks by stable lower packet-number fences. Packet-number gaps never allocate padding. Empty blocks are removed, and each block compacts/shrinks its own storage with hysteresis.

An individual insert/remove can clean up at most one small block; directory maintenance is logarithmic in block count and moves descriptors rather than all packets. This removes full-window compaction and unbounded empty-prefix/suffix scanning from an individual removal. Range iteration, ACK batches containing many removals, and connection teardown still have work proportional to what they process. Allocator delays, interrupts, and OS scheduling are not bounded by this design; it is not a hard real-time guarantee.

## Matched throughput comparison

The latest series contains **111 successful processes**: five microbenchmarks × three variants × six rounds, three fresh-process memory cases, and 18 actual encrypted QUIC transfers. All six orders of BTreeMap (`pr`), the earlier single queue with suffix cleanup (`trim`), and this block queue (`blocks`) were used. AC was checked every 100 ms during execution; the performance profile was checked before and after each process. All transfers passed completion/byte-count assertions and reported zero packet loss.

Fedora 44, Intel Core Ultra 7 155U, Rust 1.98.1 / LLVM 22.1.8; kernel `7.3.0-rc2.vanilla.fc44.20260908221956518389`. Microbenchmarks: CPU 4, at least 0.35 s. Real IPv4 loopback: client/server CPUs 0/2, one stream, 64 MiB, established encrypted connection, one second warmup, at least three seconds measurement, two seconds pause afterward. Socket buffers request 4 MiB; Linux reports 8 MiB including kernel accounting.

| Comparison | Throughput change | Process CPU time per byte change |
|---|---:|---:|
| Block queue / BTreeMap | +13.7% [+6.9%, +23.0%] | -9.1% [-15.0%, -3.8%] |
| Block queue / single queue | -1.1% [-4.7%, +2.5%] | -0.3% [-2.9%, +2.8%] |

Changes are geometric means of six matched ratios; brackets are descriptive 95% percentile bootstrap intervals from 10,000 resamples, without multiple-comparison correction. Inner iterations are not independent replicates. The block-versus-single-queue difference is not clearly resolved; throughput equivalence is not established. The original unbounded ring was not measured in this series, and earlier absolute throughput must not be mixed into it.

## Cleanup latency: same operations, three representations

Six additional AC-guarded processes measured cleanup and fragmented memory. Each implementation's cleanup process measured 32 samples for five deletion patterns at each of three window sizes, with setup outside timing. Returned packets are dropped after the timer stops, no STREAM metadata is populated, and timer overhead is included. The same generic harness is used for all versions.

The first pattern reproduces the full-window compaction trigger in the single queue. Prefix/suffix patterns expose long deleted edges. Two further patterns specifically trigger block-local compaction or removal of an empty middle block. These are deliberately constructed operation timings, not network p99 measurements, worst-case guarantees, or a paired timing study. Each variant runs in one process (order: BTreeMap, blocks, single queue); thermal/frequency/order effects remain possible.

At a 65,536-entry initial window:

| Pattern | BTreeMap median / max µs | Single queue median / max µs | Block queue median / max µs |
|---|---:|---:|---:|
| Former full-window compaction trigger | 0.557 / 0.897 | 1056.768 / 2253.404 | 0.132 / 0.264 |
| Long empty prefix | 0.650 / 0.888 | 141.085 / 223.000 | 0.357 / 0.601 |
| Long empty suffix | 0.622 / 0.892 | 70.529 / 112.324 | 0.085 / 0.256 |
| Block-local compaction trigger | 0.408 / 0.662 | 0.094 / 0.279 | 1.142 / 1.822 |
| Empty middle block | 0.725 / 0.904 | 0.080 / 0.153 | 0.672 / 1.344 |

The largest observed block-queue operation across all 15 constructed cases was **1.822 µs**. The single queue reached **2.253 ms** in this new run. The source-level block-size bound explains why the old full-window cleanup mechanism is absent; these measured maxima alone cannot establish an absolute latency ceiling.

## Costs and memory

This is a trade-off, not a universally faster representation. The block queue has more bookkeeping and is slower than the single queue in the measured packet-management microbenchmarks. Sparse successor lookup is also slower than BTreeMap. Median ns per harness operation:

| Case | BTreeMap | Single queue | Block queue |
|---|---:|---:|---:|
| `selective_16384` | 267.70 | 95.81 | 108.60 |
| `successor_65536` | 11.75 | 20.13 | 25.27 |
| `random_16384` | 537.19 | 182.61 | 272.92 |
| `dense_1024_32_meta` | 164.84 | 52.43 | 91.55 |
| `dense_16384_32` | 222.64 | 59.20 | 102.04 |

Fresh-process glibc allocator deltas (`mallinfo2().uordblks + hblkhd`, including mmap allocations), not RSS or total connection memory:

| Scenario | BTreeMap bytes | Single queue bytes | Block queue bytes |
|---|---:|---:|---:|
| One old packet across a 1,048,576-number span | 1,168 | 432 | 224 |
| One surviving packet per 64-number block, 1,024 live packets | 198,528 | 426,144 | 327,536 |

The fragmented case is deliberately unfavorable to block occupancy: the block queue uses about 65% more allocator storage than BTreeMap there, although less than the single queue. Small freed blocks can remain in allocator caches. All intermediate blocks are nonempty, block capacities are bounded, and total storage follows the live entries plus a constant allowance, rather than the packet-number span.

## Correctness and limitations

The instrumented block prototype passed **358 unit/integration tests and four doc-tests** for `quinn-proto`, `quinn`, and `quinn-udp`, including additional reference-model checks. Four pre-existing tests and five benchmark entrypoints were ignored. New tests exercise fragmented blocks, random edits to a large live window, one surviving packet per block, capacity bounds, extreme packet numbers, and range ordering. The clean review checkout separately passed 357 unit/integration tests and four doc-tests, with four pre-existing tests ignored. The published source has explanatory comments and CI formatter changes; the packet-storage algorithm matches the measured prototype.

Those components are not installed locally. Formatting changes emitted by the GitHub rustfmt check have been applied; CI lint validation is tracked on the PR. Review is still needed for directory fences, promotion between head/middle/tail, memory constants under fragmentation, and the throughput/latency trade-off. Passing tests does not establish the absence of all correctness bugs.

Temperatures at the 111-process study boundaries were **94–102 °C**. This is one laptop with dynamic frequency and background processes; affinity does not exclusively reserve CPUs. No cross-platform, real-WAN, energy-use, or hard-latency guarantees are made. Earlier battery-powered experiments and separate AC series are not pooled with these data.

## Reproduction and artifacts

From this directory in a **fresh checkout** of this draft:

```sh
python3 build.py
python3 run.py
python3 analyze.py
python3 run-cleanup.py
python3 analyze-cleanup.py
```

The builder creates detached worktrees at the pinned BTreeMap head and separate Cargo targets under ignored `local/`, then substitutes the stored single-queue reference or this checkout's block implementation. It adds identical private microbenchmark/cleanup modules and an encrypted transfer harness. Existing worktrees and measurement files are preserved by refusing to overwrite them. `--prepare-only` instead uses ignored `prepare-check/`.

The runner is Linux/glibc/Fedora-specific and assumes this machine's CPU topology and sysfs paths. Adjust those before measuring another machine. The packaging was validated by preparing all three variants and replaying the saved raw-data analysis; a complete fresh build/measurement cycle through this newly packaged builder was not repeated. The executable harnesses used for the recorded study are preserved by hashes, and the source-level harnesses are included here.

- [Latest raw observations](results/blocks-results.jsonl), [paired summary](results/blocks-summary.json), [source/executable hashes](results/blocks-manifest.json).
- [Cleanup and fragmented-memory raw data](results/cleanup-results.jsonl), [cleanup summary](results/cleanup-summary.json).
- `micro.rs`, `e2e.rs`, `cleanup-common.rs`, and `trim-reference.rs` contain the shared harness and comparison implementation.
- [Historical single-queue report](TRIM-REPORT.md) and `trim-*` results document the earlier version; its 1 ms cleanup diagnostic is superseded by the direct comparison above.
- [Earlier upstream benchmark comment](https://github.com/quinn-rs/quinn/pull/2858#issuecomment-5669458296) documents the original BTreeMap-versus-ring and broader alternative studies.

## CI audit finding

The initial GitHub audit check flags the inherited `rustls` 0.23.43 dependency (RUSTSEC-2026-0285; the job recommends >=0.23.45). Cargo.lock and all dependency manifests are unchanged from the pinned BTreeMap base. This draft does not suppress that check or incorporate an unrelated dependency update; the finding remains visible in CI.
