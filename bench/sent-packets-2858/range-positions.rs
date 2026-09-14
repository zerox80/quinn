
// Shared across BTreeMap, the published packed queue, and the optimized range.
#[test]
#[ignore]
fn range_positions() {
    let case = std::env::var("BENCH_CASE").unwrap();
    let mut m = SentPackets::default();
    let now = Instant::now();
    for pn in 0..65536 { m.insert(pn, packet(now, 1200, false)); }
    if case == "fragmented_middle" {
        for pn in 0..65536 {
            if pn % 64 != 31 { m.remove(pn); }
        }
    }
    let query = match case.as_str() {
        "head" => 7,
        "middle" => 32768,
        "tail" => 65530,
        "past_end" => 65535,
        "fragmented_middle" => 32768,
        "short_head" | "full_scan" => 0,
        _ => panic!("unknown range position"),
    };
    let expected = match case.as_str() {
        "past_end" => None,
        "fragmented_middle" => Some(32799),
        _ => Some(query + 1),
    };
    if case != "short_head" && case != "full_scan" {
        assert_eq!(m.range((Bound::Excluded(query), Bound::Unbounded)).next().map(|(pn, _)| pn), expected);
    }
    let seconds: f64 = std::env::var("BENCH_SECONDS").unwrap().parse().unwrap();
    let start = Instant::now();
    let mut count = 0u64;
    while start.elapsed().as_secs_f64() < seconds {
        for _ in 0..64 {
            if case == "full_scan" {
                black_box(black_box(&m).range(..).map(|(pn, _)| pn).sum::<u64>());
            } else if case == "short_head" {
                black_box(black_box(&m).range(black_box(0)..black_box(32)).map(|(pn, _)| pn).sum::<u64>());
            } else {
                black_box(black_box(&m).range((Bound::Excluded(black_box(query)), Bound::Unbounded)).next());
            }
            count += 1;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!("RESULT {{\"case\":\"{case}\",\"ns_op\":{},\"operations\":{count},\"seconds\":{elapsed}}}",elapsed*1e9/count as f64);
}
