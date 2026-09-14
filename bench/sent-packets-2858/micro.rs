//! Local Fedora benchmark: compiled inside the real connection module.
use super::{sent_packets::SentPackets, spaces::SentPacket};
use crate::Instant;
use std::{hint::black_box, ops::Bound, time::Duration};

fn packet(now: Instant, size: u16, metadata: bool) -> SentPacket {
    let mut p = SentPacket {
        path_generation: 0, time_sent: now, size, ack_eliciting: size != 0,
        largest_acked: None, retransmits: Default::default(), stream_frames: Default::default(),
    };
    if metadata {
        p.stream_frames.push(crate::frame::StreamMeta {
            id: crate::StreamId::new(crate::Side::Client, crate::Dir::Uni, 0),
            offsets: 0..1100, fin: false,
        });
    }
    p
}

#[test]
#[ignore]
fn measure() {
    let case = std::env::var("BENCH_CASE").unwrap();
    let now = Instant::now();
    let duration = Duration::from_secs_f64(std::env::var("BENCH_SECONDS").unwrap_or("0.6".into()).parse().unwrap());
    let mut m = SentPackets::default();
    let mut count = 0u64;
    let start;
    if case.starts_with("dense") || case.starts_with("reorder") {
        let parts: Vec<_> = case.split('_').collect();
        let live: u64 = parts[1].parse().unwrap();
        let batch: u64 = parts[2].parse().unwrap();
        let metadata = case.ends_with("meta");
        for pn in 0..live { m.insert(pn, packet(now, 1200, metadata)); }
        let mut first = 0;
        let mut acked = Vec::with_capacity(batch as usize);
        start = Instant::now();
        while start.elapsed() < duration {
            for _ in 0..128 {
                black_box(m.get(black_box(first + batch - 1)));
                acked.clear();
                acked.extend(m.range(black_box(first)..black_box(first + batch)).map(|(pn, _)| pn));
                if case.starts_with("reorder") { acked.reverse(); }
                for &pn in &acked { black_box(m.remove(black_box(pn)).unwrap()); }
                for pn in first + live..first + live + batch {
                    m.insert(black_box(pn), packet(now, 1200, metadata));
                }
                black_box(m.has_in_flight());
                first += batch;
                count += batch;
            }
        }
        assert_eq!(m.range(..).count(), live as usize);
    } else if case.starts_with("successor") {
        let gap: u64 = case.split('_').nth(1).unwrap().parse().unwrap();
        m.insert(0, packet(now, 1200, false));
        for pn in 1..gap { m.insert(pn, packet(now, 0, false)); m.remove(pn); }
        m.insert(gap, packet(now, 0, false));
        start = Instant::now();
        while start.elapsed() < duration {
            for _ in 0..64 {
                black_box(black_box(&m).range((Bound::Excluded(black_box(0)), Bound::Unbounded)).next());
                count += 1;
            }
        }
        assert_eq!(m.range(..).count(), 2);
    } else { panic!("unknown case {case}"); }
    let elapsed = start.elapsed().as_secs_f64();
    println!("RESULT {{\"case\":\"{case}\",\"ns_op\":{},\"operations\":{count},\"seconds\":{elapsed}}}", elapsed * 1e9 / count as f64);
}

// glibc allocator accounting includes mmap-backed allocations; no instrumentation
// in the hot path of the timing benchmark. Call this test alone in a fresh process.
#[repr(C)]
#[derive(Default)]
struct MallInfo { arena: usize, ordblks: usize, smblks: usize, hblks: usize, hblkhd: usize, usmblks: usize, fsmblks: usize, uordblks: usize, fordblks: usize, keepcost: usize }
unsafe extern "C" { fn mallinfo2() -> MallInfo; }
fn allocated() -> usize { let m = unsafe { mallinfo2() }; m.uordblks + m.hblkhd }

#[test]
#[ignore]
fn memory() {
    let mode = std::env::var("MEMORY_MODE").unwrap();
    let span: u64 = std::env::var("MEMORY_SPAN").unwrap().parse().unwrap();
    let now = Instant::now();
    let before = allocated();
    let mut m = SentPackets::default();
    m.insert(0, packet(now, 1200, false));
    for pn in 1..span {
        m.insert(pn, packet(now, 0, false));
        if mode == "sparse" { m.remove(pn); }
    }
    black_box(&m);
    let retained = allocated().saturating_sub(before);
    let live = m.range(..).count();
    assert!(m.has_in_flight());
    assert_eq!(m.get(0).unwrap().size, 1200);
    println!("RESULT {{\"mode\":\"{mode}\",\"span\":{span},\"live\":{live},\"allocated_bytes\":{retained},\"packet_bytes\":{},\"slot_bytes\":{}}}", std::mem::size_of::<SentPacket>(), std::mem::size_of::<Option<SentPacket>>());
}

#[test]
#[ignore]
fn ack_tail() {
    let span: u64 = std::env::var("MEMORY_SPAN").unwrap().parse().unwrap();
    let now = Instant::now();
    let before = allocated();
    let mut space = super::spaces::PacketSpace::new(now);
    space.sent(0, packet(now, 1200, false));
    let start = Instant::now();
    for pn in 1..span { black_box(space.sent(pn, packet(now, 0, false))); }
    let elapsed = start.elapsed().as_secs_f64();
    let retained = allocated().saturating_sub(before);
    let live = space.sent_packets.range(..).count();
    assert_eq!(live, 1002);
    assert!(space.has_in_flight());
    assert_eq!(space.sent_packets.get(0).unwrap().size, 1200);
    println!("RESULT {{\"mode\":\"ack_tail\",\"span\":{span},\"live\":{live},\"allocated_bytes\":{retained},\"seconds\":{elapsed}}}");
}

#[test]
#[ignore]
fn selective() {
    let case = std::env::var("BENCH_CASE").unwrap();
    let live: usize = case.split('_').nth(1).unwrap().parse().unwrap();
    let random = case.starts_with("random");
    let duration = Duration::from_secs_f64(std::env::var("BENCH_SECONDS").unwrap_or("0.35".into()).parse().unwrap());
    let now = Instant::now();
    let mut order: Vec<u64> = (live as u64/2..live as u64).chain(0..live as u64/2).collect();
    if random {
        let mut state = 2858u64;
        for i in (1..order.len()).rev() {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            order.swap(i, state as usize % (i+1));
        }
    }
    let mut m = SentPackets::default();
    let mut pn = 0;
    let mut operations = 0u64;
    let start = Instant::now();
    while start.elapsed() < duration {
        for key in pn..pn+live as u64 { m.insert(key, packet(now, 1200, true)); }
        for &offset in &order {
            black_box(m.get(black_box(pn + offset)));
            black_box(m.remove(black_box(pn + offset)).unwrap());
        }
        pn += live as u64;
        operations += live as u64;
    }
    let seconds = start.elapsed().as_secs_f64();
    assert!(!m.has_in_flight());
    println!("RESULT {{\"case\":\"{case}\",\"ns_op\":{},\"operations\":{operations},\"seconds\":{seconds}}}", seconds*1e9/operations as f64);
}

#[test]
fn differential_traces() {
    use std::collections::BTreeMap;
    for seed in 1..=12u64 {
        let now = Instant::now();
        let mut state = seed * 2858;
        let mut m = SentPackets::default();
        let mut reference = BTreeMap::new();
        let mut next_pn = 0u64;
        for step in 0..8000 {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            if state % 3 == 0 || reference.is_empty() {
                next_pn += 1 + (state >> 8) % 7;
                let size = if state & 16 == 0 { 0 } else { 1200 };
                m.insert(next_pn, packet(now, size, state & 32 == 0));
                reference.insert(next_pn, size);
            } else {
                let pn = if state & 4 == 0 { state % (next_pn+10) } else { *reference.keys().nth(state as usize % reference.len()).unwrap() };
                assert_eq!(m.remove(pn).map(|p| p.size), reference.remove(&pn));
            }
            assert_eq!(m.has_in_flight(), reference.values().any(|&s| s != 0));
            let probe = state % (next_pn+10);
            assert_eq!(m.get(probe).map(|p| p.size), reference.get(&probe).copied());
            if step % 97 == 0 {
                let actual: Vec<_> = m.range(..).map(|(n,p)|(n,p.size)).collect();
                let expected: Vec<_> = reference.iter().map(|(&n,&s)|(n,s)).collect();
                assert_eq!(actual, expected);
                let upper = probe + 1 + state % 100;
                assert_eq!(m.range(probe..=upper).map(|(n,p)|(n,p.size)).collect::<Vec<_>>(), reference.range(probe..=upper).map(|(&n,&s)|(n,s)).collect::<Vec<_>>());
                assert_eq!(m.range((Bound::Excluded(probe), Bound::Unbounded)).next().map(|(n,p)|(n,p.size)), reference.range((Bound::Excluded(probe), Bound::Unbounded)).next().map(|(&n,&s)|(n,s)));
                for p in m.values_mut() { p.path_generation += 1; }
            }
        }
        assert_eq!(m.into_values().map(|p|p.size).collect::<Vec<_>>(), reference.into_values().collect::<Vec<_>>());
    }
}

#[test]
#[ignore]
fn cleanup_comparison() {
    for n in [1024u64,16384,65536] {
        for case in ["global_compaction_pattern","prefix_pattern","suffix_pattern","block_compaction","half_block_compaction","empty_block"] {
            let mut samples=Vec::with_capacity(32);
            for _ in 0..32 {
                let now=Instant::now();
                let mut m=SentPackets::default();
                for pn in 0..n {m.insert(pn,packet(now,1200,false));}
                let b=n/2;
                let target=match case {
                    "global_compaction_pattern" => {for pn in 1..=n/2 {black_box(m.remove(pn).unwrap());} n/2+1},
                    "prefix_pattern" => {for pn in 1..=n/2 {black_box(m.remove(pn).unwrap());} 0},
                    "suffix_pattern" => {for pn in n/2..n-1 {black_box(m.remove(pn).unwrap());} n-1},
                    "block_compaction" => {for pn in b+1..=b+32 {black_box(m.remove(pn).unwrap());} b+33},
                    "half_block_compaction" => {for pn in b+1..b+32 {black_box(m.remove(pn).unwrap());} b+32},
                    "empty_block" => {for pn in b..b+63 {black_box(m.remove(pn).unwrap());} b+63},
                    _=>unreachable!(),
                };
                assert!(m.get(target).is_some());
                let start=Instant::now();
                let removed=m.remove(black_box(target)).unwrap();
                samples.push(start.elapsed().as_nanos());
                black_box(removed);
                assert!(m.get(target).is_none());
            }
            samples.sort_unstable();
            println!("RESULT {{\"case\":\"{case}\",\"window\":{n},\"samples_ns\":{samples:?}}}");
        }
    }
}

#[test]
#[ignore]
fn fragmented_memory() {
    let now=Instant::now();let before=allocated();let mut m=SentPackets::default();
    for pn in 0..65536 {m.insert(pn,packet(now,1200,false));}
    for pn in 0..65536 {if pn%64!=31 {m.remove(pn);}}
    black_box(&m);let bytes=allocated().saturating_sub(before);
    assert_eq!(m.range(..).count(),1024);
    for pn in (31..65536).step_by(64) {assert!(m.get(pn).is_some());}
    println!("RESULT {{\"case\":\"one_per_block\",\"live\":1024,\"allocated_bytes\":{bytes}}}");
}
