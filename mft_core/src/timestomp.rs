//! The SI-vs-FN MACB timestomp heuristic (§A.6).
//!
//! `$STANDARD_INFORMATION` (SI) is user-writable — the Win32 `SetFileTime` API,
//! and anti-forensic tools like `timestomp`, rewrite it — while `$FILE_NAME`
//! (FN) is updated only by the kernel on create / rename / move. SI / FN
//! divergence, and especially SI *earlier* than FN (naturally impossible), is a
//! strong anti-forensic signal. We score multiple **reasons** rather than a
//! single boolean, because the simple SI-vs-FN compare has a documented bypass
//! (timestomp SI *then* rename, so the kernel copies the stomped SI into FN).

use crate::filetime::is_zero_subsecond;
use crate::standard_info::Macb;

/// A timestomp reason token. The set is stable and surfaced as
/// `timestomp(si, fn).reasons`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// SI modified predates FN modified.
    SiBeforeFn,
    /// SI created predates FN created — impossible without tampering.
    SiCreationBeforeFnCreation,
    /// SI created and modified both fall on whole seconds (tool tell).
    ZeroSubsecond,
    /// FN created is newer than SI created (corroborating).
    FnNewerThanSi,
    /// All four SI timestamps are identical (a bulk set-all tell).
    AllFourEqual,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::SiBeforeFn => "si-before-fn",
            Reason::SiCreationBeforeFnCreation => "si-creation-before-fn-creation",
            Reason::ZeroSubsecond => "zero-subsecond",
            Reason::FnNewerThanSi => "fn-newer-than-si",
            Reason::AllFourEqual => "all-four-equal",
        }
    }
}

/// The result of the heuristic: a suspect flag and the ordered reason list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timestomp {
    pub suspect: bool,
    pub reasons: Vec<Reason>,
}

/// `true` if both operands are present and `a < b`.
fn before(a: Option<i64>, b: Option<i64>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x < y)
}

/// `true` if both operands are present and `a > b`.
fn after(a: Option<i64>, b: Option<i64>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x > y)
}

/// Score the SI-vs-FN heuristic over a record's two MACB quads.
///
/// `suspect` is set by the **strong** reasons — an impossible SI-before-FN
/// ordering or the whole-second tell — while `fn-newer-than-si` and
/// `all-four-equal` are reported as corroborating reasons but do not, on their
/// own, raise suspicion (they occur on plenty of legitimate records).
pub fn evaluate(si: &Macb, fna: &Macb) -> Timestomp {
    let mut reasons = Vec::new();

    if before(si.created, fna.created) {
        reasons.push(Reason::SiCreationBeforeFnCreation);
    }
    if before(si.modified, fna.modified) {
        reasons.push(Reason::SiBeforeFn);
    }
    // Whole-second SI created AND modified: the classic automated-tool tell.
    if is_zero_subsecond(si.created) && is_zero_subsecond(si.modified) {
        reasons.push(Reason::ZeroSubsecond);
    }
    if after(fna.created, si.created) {
        reasons.push(Reason::FnNewerThanSi);
    }
    if let (Some(c), Some(m), Some(a), Some(r)) =
        (si.created, si.modified, si.accessed, si.mft_modified)
    {
        if c == m && m == a && a == r {
            reasons.push(Reason::AllFourEqual);
        }
    }

    let suspect = reasons.iter().any(|r| {
        matches!(
            r,
            Reason::SiCreationBeforeFnCreation | Reason::SiBeforeFn | Reason::ZeroSubsecond
        )
    });

    Timestomp { suspect, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quad(c: i64, m: i64, a: i64, r: i64) -> Macb {
        Macb {
            created: Some(c),
            modified: Some(m),
            accessed: Some(a),
            mft_modified: Some(r),
        }
    }

    #[test]
    fn si_before_fn_creation_is_suspect() {
        // SI created 100, FN created 200 → impossible ordering.
        let si = quad(100, 100, 100, 100);
        let fna = quad(200, 200, 200, 200);
        let t = evaluate(&si, &fna);
        assert!(t.suspect);
        assert!(t.reasons.contains(&Reason::SiCreationBeforeFnCreation));
    }

    #[test]
    fn zero_subsecond_is_suspect() {
        // Whole-second SI (micros divisible by 1e6), FN equal → only the tell.
        let si = quad(2_000_000, 2_000_000, 2_000_000, 2_000_000);
        let fna = quad(2_000_000, 2_000_000, 2_000_000, 2_000_000);
        let t = evaluate(&si, &fna);
        assert!(t.suspect);
        assert!(t.reasons.contains(&Reason::ZeroSubsecond));
    }

    #[test]
    fn clean_record_not_suspect() {
        // SI later than FN with sub-second fractions: normal.
        let si = quad(5_000_123, 6_000_321, 6_000_321, 6_000_321);
        let fna = quad(4_000_111, 4_000_111, 4_000_111, 4_000_111);
        let t = evaluate(&si, &fna);
        assert!(!t.suspect, "reasons: {:?}", t.reasons);
    }

    #[test]
    fn rename_bypass_copies_si_into_fn() {
        // Stomped SI to whole seconds THEN renamed: FN inherits the stomp, so
        // SI==FN and there is no ordering anomaly — but the zero-subsecond tell
        // still fires (we don't over-claim, but we don't miss this either).
        let si = quad(1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000);
        let fna = si;
        let t = evaluate(&si, &fna);
        assert!(t.reasons.contains(&Reason::ZeroSubsecond));
    }
}
