> Historical report for the single-queue prototype. Reproduction commands here apply to [commit b43c6c3f](https://github.com/zerox80/quinn/tree/b43c6c3f156d3f06ee965325eafd0c108ecd3f80), not the current block-queue harness.

# Experimental bounded sent-packet queue

**AI disclosure:** OpenAI Codex implemented the prototype and benchmark harnesses, executed the measurements on the owner's Fedora laptop, and prepared the analysis and report. The owner approved publishing the work for review.

This is an experimental alternative to the BTreeMap implementation in [quinn-rs/quinn#2858](https://github.com/quinn-rs/quinn/pull/2858), based on its exact head `d11d61556d41395aedbde7ff52e0b9e1af25aa42`. It is not proposed as an immediately merge-ready replacement. The original AC comparisons and broader alternative study are documented in the [upstream benchmark comment](https://github.com/quinn-rs/quinn/pull/2858#issuecomment-5669458296).

## Implementation

The sorted queue stores explicit packet numbers and optional packets. Packet-number gaps never allocate padding. Interior deletion leaves a tombstone; empty prefixes and suffixes are reclaimed without shifting live entries. Above `max(128, 2 × live)` slots it compacts. Excess capacity is released with hysteresis. Lookup first attempts direct indexing for dense packet numbers and otherwise uses binary search.

This removes the original ring's packet-number-span-dependent allocation, while preserving a contiguous representation. It adds eight bytes per slot on this platform and does not preserve BTreeMap's logarithmic worst-case removal cost. Compaction, long empty-prefix/suffix cleanup, and shrinking can take O(n) time.

## Latest AC-powered comparison

111 successful processes: five microbenchmarks × three variants × six rounds, three fresh memory processes, and 18 actual encrypted transfers. All six permutations of BTreeMap (`pr`), the earlier bounded queue (`compact`), and the queue with suffix cleanup (`trim`) were used. AC was checked every 100 ms during processes; the performance profile was checked at boundaries. All measured transfers passed completion/byte-count assertions and reported zero packet loss.

Environment: Fedora 44, Intel Core Ultra 7 155U, Rust 1.98.1 / LLVM 22.1.8, kernel `7.3.0-rc2.vanilla.fc44.20260908221956518389`. Microbenchmarks use CPU 4 and at least 0.35 s per process. Actual QUIC transfers use client/server CPUs 0/2, one stream, 64 MiB, one second warmup, at least three seconds measurement, and two seconds pause between processes. Socket buffers request 4 MiB; Linux reports 8 MiB including kernel accounting.

| Comparison | Throughput change | Process CPU time per byte change |
|---|---:|---:|
| New queue / BTreeMap | +8.9% [+6.2%, +11.8%] | −7.3% [−10.0%, −4.6%] |
| New queue / earlier queue | +2.4% [−0.5%, +5.2%] | −1.7% [−4.4%, +1.1%] |

Changes are geometric means of six matched ratios; brackets are descriptive 95% percentile bootstrap intervals from 10,000 resamples, without correction for multiple comparisons. There is no clear additional transfer-throughput gain over the earlier queue. The original ring was not included in this new series, so its earlier absolute throughput must not be compared with these values.

In the single-old-packet / 1,048,576-packet-number-span case, allocator deltas were 432 bytes for the new queue, 26,640 bytes for the earlier queue, and 1,168 bytes for BTreeMap. These are fresh-process glibc `mallinfo2` deltas including mmap allocations, not RSS or total connection memory. Caches can retain freed small allocations.

The new suffix cleanup improved sparse successor lookup markedly, but the dense 16K microbenchmark took 4.1% longer than the earlier queue [+1.9%, +6.3%]. This is not a universally dominant data structure or an optimization with no costs.

## Open issue: individual cleanup pauses

A separate AC-guarded diagnostic deliberately constructed compaction, prefix-cleanup, and suffix-cleanup cases. Each had 32 repetitions per window size on CPU 4, with setup outside timing and no STREAM metadata. Assertions verify the intended internal state. Timing ends before the returned packet is dropped.

| Window before compaction | Median compaction | Maximum observed compaction |
|---|---:|---:|
| 1,024 | 4.988 µs | 5.505 µs |
| 16,384 | 132.216 µs | 195.484 µs |
| 65,536 | 789.191 µs | 1,007.427 µs |

These are constructed operation timings, not network p99 latency or guaranteed upper bounds. Timer overhead is included. BTreeMap was not subjected to an equivalent individual-operation diagnostic here. Long cleanup operations could stall a shared worker and are a central review concern. Incremental or block-based cleanup is a possible follow-up, not an implemented or measured solution.

This is one desktop laptop with dynamic frequency, thermal effects, and background processes. Affinity does not exclusively reserve cores. Boundary temperatures are recorded in the raw results and summary. None of these measurements establish behavior on other CPUs, real WANs, or all Quinn workloads.

## Reproduction and files

- `results/trim-results.jsonl`: all 111 raw observations, including power/temperature context.
- `results/trim-summary.json`: paired analysis and medians.
- `results/trim-latency.json`: individual cleanup diagnostic samples.
- `results/trim-manifest.json`: historical measured-source/executable hashes. Paths identify the local study layout; the executable files are not included. The review source may differ in comments, formatting, and test organization.
- `micro.rs`, `e2e.rs`, and `compact-reference.rs`: the harnesses and earlier queue reference.
- `cleanup-diagnostic.rs`: the isolated diagnostic; it uses private fields and is appended temporarily to the queue's source during diagnostic builds.

From this directory in a checkout of the review branch:

```sh
python3 build.py
python3 run.py
python3 analyze.py
```

The builder creates detached worktrees and separate Cargo target directories under ignored `local/`, leaving the checkout's production source untouched. Existing worktree directories and output data are preserved by refusing to overwrite them. The runner assumes this Fedora laptop's CPU topology and sysfs paths. Adjust them before using another machine; this is not a portable benchmark command. The runner has no fallback to battery power. It performs 111 measurement processes and does not execute the cleanup diagnostic automatically.

The cleanup diagnostic can be reproduced by appending `cleanup-diagnostic.rs` to the new queue's `sent_packets.rs` in a disposable worktree, then running its ignored test in release mode on CPU 4. The source uses the accompanying `trim_test_packet` test fixture. Use a separate target directory and remove the temporary instrumentation afterward.

The packaged builder was checked in prepare-only mode for all three variants. Its run/analysis scripts match the executed study scripts except for their output-root path, and replaying the packaged analysis on the saved raw data reproduced the summary byte-for-byte. A complete fresh build-and-measure cycle through the newly packaged builder has not been repeated.

The clean production checkout passed `cargo test --release --locked -p quinn-proto -p quinn -p quinn-udp`: 356 unit/integration tests and four doc-tests, with four pre-existing tests ignored. The source changed only in comments afterward. Formatter and Clippy checks remain outstanding because those components are not installed on the benchmark machine. The earlier instrumented prototype also passed the deterministic reference-model traces included in `micro.rs`.
