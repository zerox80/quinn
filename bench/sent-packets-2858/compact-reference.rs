use std::collections::VecDeque;
use std::ops::{Bound, RangeBounds};

use super::spaces::SentPacket;

/// Sorted packet numbers with bounded tombstones. Deletion does not move the
/// remaining packets individually. Compaction is charged to accumulated holes.
#[derive(Default)]
pub(super) struct SentPackets {
    packets: VecDeque<(u64, Option<SentPacket>)>,
    live: usize,
    in_flight: usize,
}

impl SentPackets {
    pub(super) fn insert(&mut self, pn: u64, value: SentPacket) {
        debug_assert!(self.packets.back().is_none_or(|x| x.0 < pn));
        self.in_flight += usize::from(value.size != 0);
        self.live += 1;
        self.packets.push_back((pn, Some(value)));
    }

    fn lower_bound(&self, pn: u64) -> usize {
        let Some(&(first, _)) = self.packets.front() else { return 0 };
        if pn <= first { return 0; }
        if pn > self.packets.back().unwrap().0 { return self.packets.len(); }
        if let Ok(index) = usize::try_from(pn - first) {
            if self.packets.get(index).is_some_and(|x| x.0 == pn) { return index; }
        }
        self.packets.partition_point(|x| x.0 < pn)
    }

    pub(super) fn remove(&mut self, pn: u64) -> Option<SentPacket> {
        let index = self.lower_bound(pn);
        let (key, slot) = self.packets.get_mut(index)?;
        if *key != pn { return None; }
        let value = slot.take()?;
        self.in_flight -= usize::from(value.size != 0);
        self.live -= 1;
        while self.packets.front().is_some_and(|x| x.1.is_none()) {
            self.packets.pop_front();
        }
        // At most max(128, 2 * live) slots remain after a removal.
        if self.packets.len() > 128.max(self.live.saturating_mul(2)) {
            self.packets.retain(|x| x.1.is_some());
        }
        // Also release allocation after a large window drains. Hysteresis avoids
        // shrinking on every ACK or during steady-state traffic.
        if self.packets.capacity() > 256.max(self.live.saturating_mul(4)) {
            self.packets.shrink_to(128.max(self.packets.len().saturating_mul(2)));
        }
        Some(value)
    }

    pub(super) fn get(&self, pn: u64) -> Option<&SentPacket> {
        let (key, value) = self.packets.get(self.lower_bound(pn))?;
        if *key != pn { return None; }
        value.as_ref()
    }

    pub(super) fn has_in_flight(&self) -> bool { self.in_flight != 0 }

    pub(super) fn range(&self, range: impl RangeBounds<u64>) -> impl Iterator<Item = (u64, &SentPacket)> + '_ {
        let after = |n: u64| n.checked_add(1).map_or(self.packets.len(), |n| self.lower_bound(n));
        let start = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(&n) => self.lower_bound(n),
            Bound::Excluded(&n) => after(n),
        };
        let end = match range.end_bound() {
            Bound::Unbounded => self.packets.len(),
            Bound::Included(&n) => after(n),
            Bound::Excluded(&n) => self.lower_bound(n),
        };
        self.packets.range(start..start.max(end)).filter_map(|(pn, p)| p.as_ref().map(|p| (*pn, p)))
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut SentPacket> + '_ {
        self.packets.iter_mut().filter_map(|(_, p)| p.as_mut())
    }

    pub(super) fn into_values(self) -> impl Iterator<Item = SentPacket> {
        self.packets.into_iter().filter_map(|(_, p)| p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Instant;
    use std::ops::Bound;

    #[test]
    fn storage_is_bounded_by_live_packets() {
        let mut packets = SentPackets::default();
        packets.insert(0, packet(1200));
        for pn in 1..4096 {
            packets.insert(pn, packet(0));
            packets.remove(pn);
        }
        assert_eq!(packets.range(..).count(), 1);
        assert!(packets.packets.len() <= 128);
        assert!(packets.packets.capacity() <= 256);
        assert!(packets.has_in_flight());
        assert_eq!(packets.get(0).unwrap().size, 1200);
    }

    #[test]
    fn insert_get_and_order() {
        let mut m = SentPackets::default();
        for pn in 3..=6 {
            m.insert(pn, packet(pn as u16 * 10));
        }
        assert_eq!(m.get(3).map(|p| p.size), Some(30));
        assert_eq!(m.get(6).map(|p| p.size), Some(60));
        assert!(m.get(2).is_none());
        assert!(m.get(7).is_none());
        assert_eq!(m.get(5).map(|p| p.size), Some(50));
        assert_eq!(
            m.range(..).map(|(_, p)| p.size).collect::<Vec<_>>(),
            vec![30, 40, 50, 60]
        );
    }

    #[test]
    fn skipped_numbers_leave_gaps() {
        let mut m = SentPackets::default();
        m.insert(0, packet(0));
        m.insert(1, packet(1));
        m.insert(4, packet(4)); // 2 and 3 skipped
        assert!(m.get(2).is_none());
        assert!(m.get(3).is_none());
        assert_eq!(m.get(4).map(|p| p.size), Some(4));
        assert_eq!(range_of(&m, ..), vec![(0, 0), (1, 1), (4, 4)]);
    }

    #[test]
    fn remove_middle_leaves_hole_front_unchanged() {
        let mut m = SentPackets::default();
        for pn in 0..5 {
            m.insert(pn, packet(pn as u16));
        }
        assert_eq!(m.remove(2).map(|p| p.size), Some(2));
        assert!(m.remove(2).is_none());
        assert!(m.get(2).is_none());
        // Front intact: offset unchanged, iteration skips the hole.
        assert_eq!(range_of(&m, ..), vec![(0, 0), (1, 1), (3, 3), (4, 4)]);
    }

    #[test]
    fn remove_front_reclaims_leading_holes() {
        let mut m = SentPackets::default();
        for pn in 0..5 {
            m.insert(pn, packet(pn as u16));
        }
        // Removing the front also reclaims the already-vacated 1 and 2.
        assert_eq!(m.remove(1).map(|p| p.size), Some(1));
        assert_eq!(m.remove(2).map(|p| p.size), Some(2));
        assert_eq!(m.remove(0).map(|p| p.size), Some(0));
        assert_eq!(range_of(&m, ..), vec![(3, 3), (4, 4)]);
        // A later insert still lands at the right packet number.
        m.insert(9, packet(9));
        assert_eq!(m.get(9).map(|p| p.size), Some(9));
        assert_eq!(range_of(&m, ..), vec![(3, 3), (4, 4), (9, 9)]);
    }

    #[test]
    fn range_bounds() {
        let mut m = SentPackets::default();
        for pn in 10..20 {
            m.insert(pn, packet(pn as u16));
        }
        assert_eq!(range_of(&m, 12..15), vec![(12, 12), (13, 13), (14, 14)]);
        assert_eq!(range_of(&m, 12..=14), vec![(12, 12), (13, 13), (14, 14)]);
        assert_eq!(
            range_of(&m, (Bound::Excluded(17), Bound::Unbounded)),
            vec![(18, 18), (19, 19)]
        );
        // "First entry after x", as used by `sent()`.
        assert_eq!(
            m.range((Bound::Excluded(15), Bound::Unbounded))
                .next()
                .map(|(pn, p)| (pn, p.size)),
            Some((16, 16))
        );
        // Out-of-window ranges are empty, not a panic.
        assert_eq!(range_of(&m, 0..5), vec![]);
        assert_eq!(range_of(&m, 100..200), vec![]);
    }

    #[test]
    fn values_mut_and_into_values() {
        let mut m = SentPackets::default();
        for pn in 0..4 {
            m.insert(pn, packet(pn as u16));
        }
        m.remove(1);
        for v in m.values_mut() {
            v.size += 100;
        }
        assert_eq!(m.get(0).map(|p| p.size), Some(100));
        assert_eq!(m.get(2).map(|p| p.size), Some(102));
        assert_eq!(
            m.into_values().map(|p| p.size).collect::<Vec<_>>(),
            vec![100, 102, 103]
        );
    }

    #[test]
    fn take_resets() {
        let mut m = SentPackets::default();
        for pn in 5..8 {
            m.insert(pn, packet(pn as u16));
        }
        let taken = std::mem::take(&mut m);
        assert_eq!(
            taken.into_values().map(|p| p.size).collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert_eq!(range_of(&m, ..), vec![]);
        // Reusable after take.
        m.insert(100, packet(100));
        assert_eq!(m.get(100).map(|p| p.size), Some(100));
    }

    #[test]
    fn tracks_in_flight() {
        let mut m = SentPackets::default();
        assert!(!m.has_in_flight());
        m.insert(0, packet(0)); // size 0: not in flight
        assert!(!m.has_in_flight());
        m.insert(1, packet(1200));
        m.insert(2, packet(1200));
        assert!(m.has_in_flight());
        m.remove(1);
        assert!(m.has_in_flight()); // 2 still in flight
        m.remove(2);
        assert!(!m.has_in_flight()); // only size-0 remains
        m.remove(0);
        assert!(!m.has_in_flight());
    }

    #[test]
    fn extreme_packet_number_gap() {
        let mut m = SentPackets::default();
        let last = (1u64 << 62) - 1;
        m.insert(0, packet(1200));
        m.insert(last, packet(0));
        assert_eq!(m.range(1..).next().unwrap().0, last);
        assert!(m.get(last - 1).is_none());
        assert!(m.remove(last).is_some());
        assert_eq!(m.range(..).count(), 1);
        assert!(m.has_in_flight());
    }

    #[test]
    fn allocation_follows_live_window_after_burst() {
        let mut m = SentPackets::default();
        for n in 0..16384 { m.insert(n, packet(1200)); }
        // Keep the oldest packet and delete a large suffix.
        for n in (1..16384).rev() {
            m.remove(n);
            assert!(m.packets.capacity() <= 512.max(n as usize * 8));
        }
        assert_eq!(m.range(..).count(), 1);
        assert!(m.packets.capacity() <= 256);
        for n in 16384..20000 {
            m.insert(n, packet(0));
            m.remove(n);
            assert!(m.packets.len() <= 128);
            assert!(m.packets.capacity() <= 256);
        }
    }

    /// A `SentPacket` identified by its `size`.
    fn packet(size: u16) -> SentPacket {
        SentPacket {
            path_generation: 0,
            time_sent: Instant::now(),
            size,
            ack_eliciting: false,
            largest_acked: None,
            retransmits: Default::default(),
            stream_frames: Default::default(),
        }
    }

    /// `(pn, size)` pairs from `range`.
    fn range_of<R: RangeBounds<u64>>(m: &SentPackets, r: R) -> Vec<(u64, u16)> {
        m.range(r).map(|(pn, v)| (pn, v.size)).collect()
    }
}
