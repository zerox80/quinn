use super::spaces::SentPacket;
use std::{
    collections::{BTreeMap, VecDeque},
    ops::{Bound, RangeBounds},
};

// No packet cleanup operation visits more than one block. The directory moves
// block descriptors, never all packets, when a block becomes empty.
const BLOCK_SIZE: usize = 64;
type Bounds = (Bound<u64>, Bound<u64>);

#[derive(Default)]
struct Block {
    slots: VecDeque<(u64, Option<SentPacket>)>,
    live: usize,
}

impl Block {
    fn is_empty(&self) -> bool {
        self.live == 0
    }
    fn first(&self) -> u64 {
        self.slots.front().unwrap().0
    }
    fn last(&self) -> u64 {
        self.slots.back().unwrap().0
    }
    fn make_room(&mut self) -> bool {
        if self.slots.len() == BLOCK_SIZE && self.live < BLOCK_SIZE {
            self.slots.retain(|(_, p)| p.is_some());
        }
        self.slots.len() < BLOCK_SIZE
    }
    fn insert(&mut self, pn: u64, packet: SentPacket) {
        debug_assert!(self.slots.len() < BLOCK_SIZE);
        debug_assert!(self.is_empty() || self.last() < pn);
        self.slots.push_back((pn, Some(packet)));
        self.live += 1;
    }
    fn lower_bound(&self, pn: u64) -> usize {
        if self.is_empty() || pn <= self.first() {
            return 0;
        }
        if pn > self.last() {
            return self.slots.len();
        }
        if let Ok(i) = usize::try_from(pn - self.first())
            && self.slots.get(i).is_some_and(|(key, _)| *key == pn)
        {
            return i;
        }
        self.slots.partition_point(|(key, _)| *key < pn)
    }
    fn get(&self, pn: u64) -> Option<&SentPacket> {
        let (key, p) = self.slots.get(self.lower_bound(pn))?;
        if *key != pn {
            return None;
        }
        p.as_ref()
    }
    fn remove(&mut self, pn: u64) -> Option<SentPacket> {
        let i = self.lower_bound(pn);
        let (key, p) = self.slots.get_mut(i)?;
        if *key != pn {
            return None;
        }
        let p = p.take()?;
        self.live -= 1;
        while self.slots.front().is_some_and(|(_, p)| p.is_none()) {
            self.slots.pop_front();
        }
        while self.slots.back().is_some_and(|(_, p)| p.is_none()) {
            self.slots.pop_back();
        }
        if self.slots.len() > 4.max(self.live * 2) {
            self.slots.retain(|(_, p)| p.is_some());
        }
        if self.slots.capacity() > (self.live * 2).max(2).next_power_of_two() {
            self.slots
                .shrink_to(self.slots.len().max(2).next_power_of_two());
        }
        Some(p)
    }
    fn range(&self, bounds: Bounds) -> impl Iterator<Item = (u64, &SentPacket)> {
        let after = |pn: u64| {
            pn.checked_add(1)
                .map_or(self.slots.len(), |pn| self.lower_bound(pn))
        };
        let start = match bounds.0 {
            Bound::Unbounded => 0,
            Bound::Included(pn) => self.lower_bound(pn),
            Bound::Excluded(pn) => after(pn),
        };
        let end = match bounds.1 {
            Bound::Unbounded => self.slots.len(),
            Bound::Included(pn) => after(pn),
            Bound::Excluded(pn) => self.lower_bound(pn),
        };
        self.slots
            .range(start..start.max(end))
            .filter_map(|(pn, p)| p.as_ref().map(|p| (*pn, p)))
    }
    fn values_mut(&mut self) -> impl Iterator<Item = &mut SentPacket> {
        self.slots.iter_mut().filter_map(|(_, p)| p.as_mut())
    }
    fn into_values(self) -> impl Iterator<Item = SentPacket> {
        self.slots.into_iter().filter_map(|(_, p)| p)
    }
}

/// A bounded-block queue with direct access to its oldest and newest blocks.
/// Interior blocks are indexed by their original lower packet-number fence.
///
/// Packet-number gaps never allocate padding. Cleaning up a packet visits at most
/// one block of 64 slots; directory operations remain logarithmic in block count.
/// A range or a batch of removals can still process many packets.
#[derive(Default)]
pub(super) struct SentPackets {
    head: Block,
    middle: BTreeMap<u64, Block>,
    tail: Block,
    in_flight: usize,
}
impl SentPackets {
    pub(super) fn insert(&mut self, pn: u64, packet: SentPacket) {
        self.in_flight += usize::from(packet.size != 0);
        if self.head.is_empty()
            || (self.middle.is_empty() && self.tail.is_empty() && self.head.make_room())
        {
            self.head.insert(pn, packet);
        } else {
            if !self.tail.make_room() {
                let block = std::mem::take(&mut self.tail);
                self.middle.insert(block.first(), block);
            }
            self.tail.insert(pn, packet);
        }
    }
    pub(super) fn get(&self, pn: u64) -> Option<&SentPacket> {
        if self.head.is_empty() {
            return None;
        }
        if pn <= self.head.last() {
            return self.head.get(pn);
        }
        if !self.tail.is_empty() && pn >= self.tail.first() {
            return self.tail.get(pn);
        }
        self.middle.range(..=pn).next_back()?.1.get(pn)
    }
    pub(super) fn remove(&mut self, pn: u64) -> Option<SentPacket> {
        if self.head.is_empty() {
            return None;
        }
        let packet = if pn <= self.head.last() {
            self.head.remove(pn)
        } else if !self.tail.is_empty() && pn >= self.tail.first() {
            self.tail.remove(pn)
        } else {
            let (&key, block) = self.middle.range_mut(..=pn).next_back()?;
            let packet = block.remove(pn);
            if block.is_empty() {
                self.middle.remove(&key);
            }
            packet
        }?;
        self.in_flight -= usize::from(packet.size != 0);
        if self.head.is_empty() {
            self.head = self
                .middle
                .pop_first()
                .map_or_else(|| std::mem::take(&mut self.tail), |(_, b)| b);
        }
        Some(packet)
    }
    pub(super) fn has_in_flight(&self) -> bool {
        self.in_flight != 0
    }
    pub(super) fn range(
        &self,
        range: impl RangeBounds<u64>,
    ) -> impl Iterator<Item = (u64, &SentPacket)> {
        let bounds = (range.start_bound().cloned(), range.end_bound().cloned());
        let lower = match bounds.0 {
            Bound::Unbounded => 0,
            Bound::Included(n) | Bound::Excluded(n) => n,
        };
        let start = self
            .middle
            .range(..=lower)
            .next_back()
            .map_or(lower, |(&n, _)| n);
        let end = match bounds.1 {
            Bound::Unbounded => u64::MAX,
            Bound::Included(n) | Bound::Excluded(n) => n,
        };
        self.head
            .range(bounds)
            .chain(
                self.middle
                    .range(start..=start.max(end))
                    .flat_map(move |(_, b)| b.range(bounds)),
            )
            .chain(self.tail.range(bounds))
    }
    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut SentPacket> {
        self.head
            .values_mut()
            .chain(self.middle.values_mut().flat_map(Block::values_mut))
            .chain(self.tail.values_mut())
    }
    pub(super) fn into_values(self) -> impl Iterator<Item = SentPacket> {
        self.head
            .into_values()
            .chain(self.middle.into_values().flat_map(Block::into_values))
            .chain(self.tail.into_values())
    }
    #[cfg(test)]
    fn capacity_slots(&self) -> usize {
        self.head.slots.capacity()
            + self.tail.slots.capacity()
            + self
                .middle
                .values()
                .map(|b| b.slots.capacity())
                .sum::<usize>()
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
        assert!(packets.capacity_slots() <= 8);
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
        for n in 0..16384 {
            m.insert(n, packet(1200));
        }
        // Keep the oldest packet and delete a large suffix.
        for n in (1..16384).rev() {
            m.remove(n);
            assert!(m.capacity_slots() <= 512.max(n as usize * 8));
        }
        assert_eq!(m.range(..).count(), 1);
        assert!(m.capacity_slots() <= 256);
        for n in 16384..20000 {
            m.insert(n, packet(0));
            m.remove(n);
            assert!(m.range(..).count() <= 128);
            assert!(m.capacity_slots() <= 256);
        }
    }

    #[test]
    fn fragmented_blocks_match_reference() {
        use std::collections::BTreeMap;
        for seed in 1..=4u64 {
            let mut m = SentPackets::default();
            let mut reference = BTreeMap::new();
            for pn in 0..4096 {
                m.insert(pn, packet(1200));
                reference.insert(pn, 1200);
            }
            let mut state = seed * 2858;
            let mut next = 4096;
            for step in 0..8192 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if state.is_multiple_of(3) || reference.is_empty() {
                    next += 1 + (state >> 8) % 7;
                    let size = if state & 16 == 0 { 0 } else { 1200 };
                    m.insert(next, packet(size));
                    reference.insert(next, size);
                } else {
                    let pn = *reference
                        .keys()
                        .nth(state as usize % reference.len())
                        .unwrap();
                    assert_eq!(m.remove(pn).map(|p| p.size), reference.remove(&pn));
                }
                for block in std::iter::once(&m.head)
                    .chain(m.middle.values())
                    .chain(std::iter::once(&m.tail))
                {
                    assert!(block.slots.len() <= BLOCK_SIZE);
                    assert!(block.slots.capacity() <= BLOCK_SIZE);
                    assert_eq!(
                        block.live,
                        block.slots.iter().filter(|(_, p)| p.is_some()).count()
                    );
                }
                assert!(m.middle.values().all(|b| !b.is_empty()));
                assert!(!m.head.is_empty() || (m.middle.is_empty() && m.tail.is_empty()));
                assert_eq!(m.has_in_flight(), reference.values().any(|&size| size != 0));
                if step % 97 == 0 {
                    assert_eq!(
                        range_of(&m, ..),
                        reference.iter().map(|(&k, &v)| (k, v)).collect::<Vec<_>>()
                    );
                    let lower = state % (next + 1);
                    let upper = lower + state % 1000;
                    assert_eq!(
                        range_of(&m, lower..=upper),
                        reference
                            .range(lower..=upper)
                            .map(|(&k, &v)| (k, v))
                            .collect::<Vec<_>>()
                    );
                    assert!(
                        m.range((Bound::Excluded(u64::MAX), Bound::Unbounded))
                            .next()
                            .is_none()
                    );
                }
            }
            for (pn, size) in reference {
                assert_eq!(m.remove(pn).map(|p| p.size), Some(size));
            }
            assert!(m.head.is_empty() && m.middle.is_empty() && m.tail.is_empty());
        }
    }

    #[test]
    fn one_live_packet_per_block_releases_capacity() {
        let mut m = SentPackets::default();
        for pn in 0..65536 {
            m.insert(pn, packet(1200));
        }
        for pn in 0..65536 {
            if pn % 64 != 31 {
                m.remove(pn);
            }
        }
        assert_eq!(m.range(..).count(), 1024);
        assert!(m.capacity_slots() <= 4096);
        for pn in (31..65536).step_by(64) {
            assert_eq!(m.get(pn).unwrap().size, 1200);
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
