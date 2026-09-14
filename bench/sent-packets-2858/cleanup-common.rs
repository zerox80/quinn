
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
