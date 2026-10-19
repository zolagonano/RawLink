//! Sliding-window anti-replay detector for received packet numbers.
//!
//! Mirrors the IPSec/QUIC approach: track the highest authenticated PN and
//! a 128-bit bitmap covering the 128 PNs below it. A PN is accepted iff it
//! is new (above `max_pn`, or falling inside the window at an unset bit).
//! Marks are made ONLY after the packet has authenticated successfully, so
//! an attacker cannot burn window bits with unauthenticated garbage.
//!
//! On a TCP carrier packets arrive in order, so in practice every old PN is
//! a replay; the bitmap keeps the detector correct even if a carrier
//! reorders (e.g. the sim carrier with variable delay).

const WINDOW_BITS: u64 = 128;

#[derive(Debug)]
pub struct ReplayWindow {
    /// Highest PN ever accepted (0 = none yet; real PNs start at 1).
    max_pn: u64,
    /// Bit i (0..=127) set means `max_pn - i` was already accepted.
    /// Bit 0 corresponds to `max_pn` itself.
    bitmap: [u64; 2],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            max_pn: 0,
            bitmap: [0; 2],
        }
    }

    /// Check whether `pn` is a duplicate/replay WITHOUT marking it.
    pub fn is_duplicate(&self, pn: u64) -> bool {
        if pn == 0 {
            return true;
        }
        if pn > self.max_pn {
            return false;
        }
        let age = self.max_pn - pn;
        if age >= WINDOW_BITS {
            return true;
        }
        let (word, bit) = ((age / 64) as usize, (age % 64) as u32);
        self.bitmap[word] & (1u64 << bit) != 0
    }

    /// Mark `pn` as seen. Only call after a successful authenticity check.
    /// Returns false if the PN was already marked (duplicate).
    pub fn mark(&mut self, pn: u64) -> bool {
        if pn == 0 {
            return false;
        }
        if pn > self.max_pn {
            // Shift the window forward. PNs that fall out of the bottom
            // are implicitly "seen" (they are older than the window and
            // is_duplicate() already rejects them by age).
            let shift = (pn - self.max_pn) as u32;
            self.max_pn = pn;
            if shift >= WINDOW_BITS as u32 {
                self.bitmap = [0; 2];
            } else if shift >= 64 {
                self.bitmap = [0, self.bitmap[0] << (shift - 64)];
            } else if shift > 0 {
                self.bitmap = [
                    (self.bitmap[0] << shift) | (self.bitmap[1] >> (64 - shift)),
                    (self.bitmap[1] << shift) | (self.bitmap[0] >> (64 - shift)),
                ];
            }
            // Set bit 0 (== max_pn).
            self.bitmap[0] |= 1;
            return true;
        }
        let age = self.max_pn - pn;
        if age >= WINDOW_BITS {
            return false;
        }
        let (word, bit) = ((age / 64) as usize, (age % 64) as u32);
        let mask = 1u64 << bit;
        if self.bitmap[word] & mask != 0 {
            return false; // duplicate
        }
        self.bitmap[word] |= mask;
        true
    }

    #[allow(dead_code)] // exposed for diagnostics/tests
    pub fn max_pn(&self) -> u64 {
        self.max_pn
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_first_and_sequential_pns() {
        let mut w = ReplayWindow::new();
        assert!(!w.is_duplicate(1));
        assert!(w.mark(1));
        for pn in 2..200u64 {
            assert!(!w.is_duplicate(pn), "pn {pn} wrongly flagged");
            assert!(w.mark(pn), "pn {pn} mark failed");
        }
    }

    #[test]
    fn rejects_exact_replays() {
        let mut w = ReplayWindow::new();
        for pn in 1..50u64 {
            w.mark(pn);
        }
        for pn in 1..50u64 {
            assert!(w.is_duplicate(pn), "replay of pn {pn} not detected");
            assert!(!w.mark(pn), "replay of pn {pn} re-marked");
        }
    }

    #[test]
    fn rejects_replays_older_than_window() {
        let mut w = ReplayWindow::new();
        for pn in 1..500u64 {
            w.mark(pn);
        }
        assert!(w.is_duplicate(1));
        assert!(w.is_duplicate(300));
        assert!(w.is_duplicate(371)); // 499 - 128 → just outside window
        // 500 was never received and is above max → genuinely new.
        assert!(!w.is_duplicate(500));
    }

    #[test]
    fn handles_reordered_arrival() {
        let mut w = ReplayWindow::new();
        assert!(w.mark(10));
        // Late arrival within the window is accepted once.
        assert!(!w.is_duplicate(8));
        assert!(w.mark(8));
        assert!(w.is_duplicate(8));
        // Jump the window far ahead; now pn=1 is older than the window.
        assert!(w.mark(200));
        assert!(w.is_duplicate(1));
        assert!(!w.mark(1));
    }

    #[test]
    fn rejects_pn_zero() {
        let mut w = ReplayWindow::new();
        assert!(w.is_duplicate(0));
        assert!(!w.mark(0));
    }

    #[test]
    fn window_shifts_correctly_across_word_boundary() {
        let mut w = ReplayWindow::new();
        for pn in 1..=200u64 {
            assert!(w.mark(pn));
        }
        // pn 100 is 100 below max 200 → still inside the 128-bit window.
        assert!(w.is_duplicate(100));
        // pn 71 is 129 below max 200 → outside → treated as replay by age.
        assert!(w.is_duplicate(71));
        // A brand-new far-future pn clears the bitmap and stays acceptable.
        assert!(w.mark(10_000));
        // 9_999 sits inside the fresh window but was never marked after the
        // jump — standard sliding-window semantics treat it as new (the
        // per-stream DATA offset check is the second line of defense).
        assert!(!w.is_duplicate(9_999));
        assert!(!w.is_duplicate(10_050));
        // 9_700 is 300 below max → rejected by age.
        assert!(w.is_duplicate(9_700));
    }
}
