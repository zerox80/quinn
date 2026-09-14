
#[cfg(test)]
mod trim_latency {
    use super::*;
    use std::{hint::black_box, time::Instant};

    #[test]
    #[ignore]
    fn measure_cleanup_pauses() {
        for n in [1024u64, 16384, 65536] {
            let mut regular = Vec::new();
            let mut compact = Vec::new();
            let mut prefix = Vec::new();
            let mut suffix = Vec::new();
            for _ in 0..32 {
                // Keep both endpoints live; the first timed removal does not
                // compact, the second crosses exactly the 50% live threshold.
                let mut m = SentPackets::default();
                for pn in 0..n { m.insert(pn, trim_test_packet(1200)); }
                for pn in 1..n/2 { black_box(m.remove(pn).unwrap()); }
                let start = Instant::now();
                let p = m.remove(black_box(n/2)).unwrap();
                regular.push(start.elapsed().as_nanos());
                black_box(p);
                assert_eq!(m.packets.len(), n as usize);
                let start = Instant::now();
                let p = m.remove(black_box(n/2+1)).unwrap();
                compact.push(start.elapsed().as_nanos());
                black_box(p);
                assert_eq!(m.packets.len(), m.live);

                let mut m = SentPackets::default();
                for pn in 0..n { m.insert(pn, trim_test_packet(1200)); }
                for pn in 1..=n/2 { black_box(m.remove(pn).unwrap()); }
                assert_eq!(m.packets.len(), n as usize);
                let start = Instant::now();
                let p = m.remove(black_box(0)).unwrap();
                prefix.push(start.elapsed().as_nanos());
                black_box(p);
                assert_eq!(m.packets.len(), m.live);

                let mut m = SentPackets::default();
                for pn in 0..n { m.insert(pn, trim_test_packet(1200)); }
                for pn in n/2..n-1 { black_box(m.remove(pn).unwrap()); }
                assert_eq!(m.packets.len(), n as usize);
                let start = Instant::now();
                let p = m.remove(black_box(n-1)).unwrap();
                suffix.push(start.elapsed().as_nanos());
                black_box(p);
                assert_eq!(m.packets.len(), m.live);
            }
            for (case, mut values) in [("regular",regular),("compaction",compact),("prefix_cleanup",prefix),("suffix_cleanup",suffix)] {
                values.sort_unstable();
                println!("RESULT {{\"case\":\"{case}\",\"window\":{n},\"samples_ns\":{values:?}}}");
            }
        }
    }
}
