# Packed bounded-block sent-packet queue: experimental review

Historical report for published commit `b7839fd60512079e9207b9867666ad3fa24db533`, before the direct successor lookup. See [the current report](README.md) for the latest implementation and measurements. The reproduction section below describes the packaging at that historical commit.

**AI disclosure:** OpenAI Codex implemented these prototypes and harnesses, executed the measurements on the owner's Fedora laptop, and prepared this report. The owner requested publication for review.

This draft explores an alternative to [quinn-rs/quinn#2858](https://github.com/quinn-rs/quinn/pull/2858), pinned to `d11d61556d41395aedbde7ff52e0b9e1af25aa42`. The current implementation (`packed`) keeps cleanup local to 64-slot blocks and reduces storage in sparsely occupied intermediate blocks. The previously published block queue (`blocks`) and upstream BTreeMap (`pr`) are the controls. This is an experimental trade-off requiring review.

## Representation and memory

The oldest and newest blocks use `VecDeque` for append and edge removal. A `BTreeMap` directory indexes intermediate blocks by stable lower packet-number fences. Intermediate blocks never append, so they now use boxed slices: a smaller descriptor and no spare vector capacity. When occupancy reaches half, only that block is compacted to exactly its live entries; a singleton therefore retains one slot. Promotion to a mutable edge block converts at most 64 slots. Packet-number gaps never allocate padding.

An individual insert/remove can clean up at most one small block. Directory maintenance is logarithmic in block count and moves descriptors, not the whole packet window. ACK batches, iteration and teardown still do work proportional to what they process. OS scheduling and allocator delays have no hard bound.

Fresh-process glibc allocator deltas (`mallinfo2().uordblks + hblkhd`, including mmap allocations), not RSS or total connection memory:

| Scenario | BTreeMap bytes | Previous blocks bytes | Packed blocks bytes |
|---|---:|---:|---:|
| One old packet across a 1,048,576-number span | 1,168 | 224 | 224 |
| One surviving packet per 64-number block, 1,024 live packets | 198,528 | 327,536 | **182,976** |

In this deliberately fragmented case, packing reduces storage **44.1% relative to the previous block queue**, and puts it **7.8% below BTreeMap**. The previous approximately 65% overhead is removed in this exact case. This is not a claim that packed blocks always use less memory; allocator caches, block occupancy and other live-window patterns matter. A regression test checks retained slot capacity for this pattern.

## Matched encrypted-transfer comparison

Fedora 44, Intel Core Ultra 7 155U, Rust 1.98.1 / LLVM 22.1.8, kernel `7.3.0-rc2.vanilla.fc44.20260908221956518389`. Separate optimized executables and Cargo target directories per variant. IPv4 loopback, client/server CPUs 0/2, one stream, 64 MiB, established encrypted connection, one second warmup, at least three seconds measurement, two seconds pause afterward. Requested socket buffers: 4 MiB (Linux reports 8 MiB including accounting).

The initial packed study contains **129 successful processes**: five microbenchmarks × three variants × six rounds, three sparse memory processes and 12 matched rounds of real QUIC transfers (36 processes). All six variant permutations occurred twice for transfers. AC was checked every 100 ms, with performance profile checks at process boundaries. Transfers passed completion/byte-count assertions and reported zero loss.

| Initial packed study | Throughput change | Process CPU time per byte change |
|---|---:|---:|
| Packed / BTreeMap | +7.6% [+5.3%, +9.6%] | -4.9% [-6.8%, -2.9%] |
| Packed / previous blocks | -1.5% [-3.4%, +0.7%] | +1.3% [-0.7%, +3.4%] |

Changes are geometric means of matched per-round ratios. Brackets are descriptive 95% percentile bootstrap intervals from 10,000 resamples; inner transfers are not independent replicates, and no multiple-comparison correction is applied. The small packed-versus-previous-blocks difference does **not** establish throughput equivalence or rule out a regression.

The owner subsequently reported having Firefox open during some measurement work. The exact run mapping and browser activity were not recorded for the initial studies. This is an additional timing confounder, especially for small differences; it does not add Firefox's allocations to the benchmark process's allocator delta. A separate Firefox-closed control is reported below rather than pooled with these data.

### Separate Firefox-closed control

**72 additional successful transfer processes**, arranged as 24 matched triplets. Each of the six permutations appears four times, shuffled with fixed seed 285805 before measurement. The exact same three executables and transfer parameters were reused. Absence of an interactive Firefox instance, AC and the performance profile were checked at approximately 100 ms intervals and at boundaries; raw guard observations are included. Fedora's idle GNOME D-Bus activation service (`firefox --dbus-service`) remained and was deliberately ignored. No build or test suite ran during these timings. This is a separate control, not a randomized Firefox-on/off experiment, so it cannot isolate Firefox as a causal explanation for earlier differences.

| Firefox-closed control | Throughput change | Process CPU time per byte change |
|---|---:|---:|
| Packed / BTreeMap | +5.8% [+3.8%, +8.1%] | -4.6% [-6.8%, -2.6%] |
| Packed / previous blocks | -1.4% [-4.6%, +1.4%] | +1.5% [-0.8%, +4.1%] |

All transfers passed byte-count/completion assertions and reported zero loss. Observed temperatures, including guard samples: 94.0–101.0 °C. The same descriptive bootstrap method is used; these intervals describe this session and do not guarantee equivalence or performance on other machines.


## Microbenchmarks and remaining costs

Initial packed-study medians, ns per harness operation (CPU 4, at least 0.35 s per process):

| Case | BTreeMap | Previous blocks | Packed blocks |
|---|---:|---:|---:|
| `selective_16384` | 265.80 | 110.84 | 112.89 |
| `successor_65536` | 10.32 | 21.84 | 27.97 |
| `random_16384` | 455.41 | 258.18 | 223.47 |
| `dense_1024_32_meta` | 141.32 | 85.71 | 81.78 |
| `dense_16384_32` | 200.93 | 91.38 | 87.78 |

Sparse successor lookup remains slower than BTreeMap and became slower than the previous block queue in this study. The paired selective-removal result was approximately 4.6% slower than the previous queue. Dense and random-removal cases improved. Added head/middle/tail transitions, two block representations and duplicated lookup/range logic remain complexity costs; this is not an improvement in every workload.

## Cleanup diagnostics

Six additional AC-guarded processes measured cleanup (one process per variant) and fragmented memory (one fresh process per variant). The revised shared cleanup harness explicitly includes **both** compaction thresholds: the previous queue's trigger and the packed queue's earlier half-occupancy trigger. Each of six patterns at three window sizes has 32 samples, with setup outside timing. Returned packets are dropped after timing, STREAM metadata is absent, and timer overhead is included. Variant order is BTreeMap, previous blocks, packed; order and thermal effects remain possible.

At a 65,536-entry initial window, median / maximum in microseconds:

| Pattern | BTreeMap | Previous blocks | Packed blocks |
|---|---:|---:|---:|
| Former full-window trigger | 0.706 / 0.993 | 0.102 / 0.275 | 0.113 / 0.303 |
| Long empty prefix | 0.679 / 1.187 | 0.261 / 0.382 | 0.491 / 0.900 |
| Long empty suffix | 0.485 / 1.024 | 0.065 / 0.234 | 0.098 / 0.294 |
| Previous block compaction trigger | 0.462 / 0.778 | 1.573 / 2.128 | 0.149 / 0.280 |
| Packed half-occupancy trigger | 0.471 / 0.662 | 0.131 / 0.190 | 0.684 / 1.241 |
| Empty middle block | 0.778 / 1.099 | 0.448 / 0.813 | 0.484 / 1.292 |

The largest packed sample across all 18 constructed cases was **1.292 µs**. At its actual half-occupancy compaction trigger, the 65,536-window median was 0.684 µs and maximum 1.241 µs. These are individual operation diagnostics, **not network p99 values, worst-case guarantees or independent process replicates**. The source-level 64-slot limit removes the old global-compaction mechanism, but cannot impose a wall-clock deadline. The earlier single-queue prototype reached 2.253 ms in a separate diagnostic; that pause was not a BTreeMap problem. See the historical report rather than comparing maxima across series as a controlled ratio.

## Correctness and validation

The clean review checkout passed `cargo test --release --locked -p quinn-proto -p quinn -p quinn-udp`: **358 unit/integration tests and four doc-tests**, with four pre-existing tests ignored. `cargo fmt --all -- --check` and `cargo clippy --locked --all-targets -- -D warnings` also passed using locally extracted matching Fedora tool packages; no system package/configuration change was needed.

Regression tests cover reference-model traces over a large live window, fragmented blocks, one survivor per block, retained capacity, extreme packet numbers, ordered ranges, and exact half-occupancy compaction. The benchmark harness includes additional deterministic reference-model traces. Formatting, Clippy-equivalent expressions and regression tests differ from the measured prototype; the packet-storage algorithm is unchanged. Original source/executable hashes are retained in the manifests.

Review is still needed for stable directory fences, edge promotion, iterator correctness, memory constants and complexity. Passing tests is not proof that no correctness bugs remain.

## Reproduction and artifacts

From this directory in a fresh checkout:

```sh
python3 build.py
python3 run.py
python3 analyze.py
python3 run-cleanup.py
python3 analyze-cleanup.py
# Close Firefox completely before the separate transfer control:
python3 run-control.py
python3 analyze-control.py
```

The builder creates detached worktrees at the pinned BTreeMap head, substitutes `blocks-reference.rs` or the current packed implementation, and adds identical private microbenchmark/cleanup modules and the encrypted-transfer harness. Each variant has its own target directory. `--prepare-only` uses ignored `packed-prepare-check/`; real builds and runs use ignored `local/`. Existing worktrees/results are preserved by refusing to overwrite them. The runner assumes this laptop's topology and sysfs paths and Linux/glibc; adapt these for another machine.

Packaging was validated by preparing all variants, checking Python syntax, and replaying the saved analyses. A complete fresh build-and-measure cycle through the repackaged builder was not repeated. Recorded measurements used preserved executables whose hashes are included.

- [Initial packed observations](results/packed-results.jsonl), [summary](results/packed-summary.json), [source/executable hashes](results/packed-manifest.json).
- [Revised cleanup and fragmented-memory observations](results/packed-cleanup-v2-results.jsonl), [summary](results/packed-cleanup-v2-summary.json).
- [Firefox-closed control observations](results/packed-control-results.jsonl), [summary](results/packed-control-summary.json), [manifest](results/packed-control-manifest.json).
- `micro.rs`, `e2e.rs`, `cleanup-common.rs`, and `blocks-reference.rs` contain harnesses and the prior block reference.
- [Historical block-queue report](BLOCKS-REPORT.md), [single-queue report](TRIM-REPORT.md), and their raw results are retained for provenance, not pooled into the current comparison.
- [Earlier upstream benchmark comment](https://github.com/quinn-rs/quinn/pull/2858#issuecomment-5669458296) covers the original ring comparison and earlier alternatives.

This is one thermally stressed laptop with dynamic frequency, desktop background activity and non-exclusive CPU affinity. Initial packed-study boundary temperatures were 94.0–101.0 °C. Closing Firefox does not eliminate the remaining desktop, thermal or order confounders. No cross-platform, WAN, energy-use or hard-latency guarantee is established.

## Inherited CI audit finding

The earlier GitHub audit check flagged inherited `rustls` 0.23.43 (RUSTSEC-2026-0285; the job recommended >=0.23.45). Cargo.lock and dependency manifests are unchanged from the pinned BTreeMap base. This draft does not suppress that check or include an unrelated dependency update.
