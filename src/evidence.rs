//! Stable, conservative evidence labels for downstream Cheatarium consumers.
//!
//! These are categorical descriptions of observations, never confidence
//! probabilities, Nintendo signature checks, or executable/title attribution.

use crate::package::{HashStatus, HeaderStatus, MatchStatus, PackageAudit};
use crate::title_inventory::{TitleRecord, VersionCollision};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageEvidence {
    MetadataOnly,
    NoReferencedContent,
    Incomplete,
    SizeMatched,
    HashIncomplete,
    HashMismatched,
    HashMatchedToSuppliedCnmt,
}

impl PackageEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata_only",
            Self::NoReferencedContent => "no_referenced_content",
            Self::Incomplete => "incomplete",
            Self::SizeMatched => "filename_size_matched",
            Self::HashIncomplete => "hash_incomplete",
            Self::HashMismatched => "hash_mismatched_to_supplied_cnmt",
            Self::HashMatchedToSuppliedCnmt => "hash_matched_to_supplied_cnmt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderEvidence {
    NotChecked,
    NoReferencedContent,
    Unavailable,
    NotComparable,
    AllConsistent,
    Conflict,
    MixedOrIncomplete,
}

impl HeaderEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::NoReferencedContent => "no_referenced_content",
            Self::Unavailable => "unavailable",
            Self::NotComparable => "not_comparable",
            Self::AllConsistent => "all_readable_headers_consistent",
            Self::Conflict => "header_conflict",
            Self::MixedOrIncomplete => "mixed_or_incomplete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseEvidence {
    UniqueWithinSuppliedDataset,
    DuplicateSameCnmt,
    DuplicateConflictingCnmt,
}

impl ReleaseEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UniqueWithinSuppliedDataset => "unique_within_supplied_dataset",
            Self::DuplicateSameCnmt => "duplicate_identical_cnmt",
            Self::DuplicateConflictingCnmt => "duplicate_conflicting_cnmt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheatTarget {
    MissingBuildId,
    UnverifiedCandidateOnly,
    ConflictingRelease,
}

impl CheatTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingBuildId => "missing_build_id",
            Self::UnverifiedCandidateOnly => "unverified_candidate_only",
            Self::ConflictingRelease => "conflicting_release",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub package: PackageEvidence,
    pub headers: HeaderEvidence,
    pub release: ReleaseEvidence,
    /// An explicitly designated main.nso is never bound to a title by these
    /// checks, even when the sibling package matches an external CNMT hash.
    pub executable_association: &'static str,
    /// No observation here authorizes automatic cheat attachment.
    pub cheat_target: CheatTarget,
    pub automatic_cheat_match_allowed: bool,
}

fn package_evidence(audit: Option<&PackageAudit>) -> PackageEvidence {
    let Some(audit) = audit else {
        return PackageEvidence::MetadataOnly;
    };
    if audit.referenced.is_empty() {
        return PackageEvidence::NoReferencedContent;
    }
    // A demonstrable digest conflict takes precedence over other incomplete
    // entries, which remain visible in the full nested package audit.
    if audit.hashing_requested && audit.hash_count(HashStatus::Mismatched) != 0 {
        return PackageEvidence::HashMismatched;
    }
    if audit.count(MatchStatus::Present) != audit.referenced.len() {
        return PackageEvidence::Incomplete;
    }
    if audit.hashing_requested {
        if audit.all_hashes_match_supplied_cnmt() {
            PackageEvidence::HashMatchedToSuppliedCnmt
        } else {
            PackageEvidence::HashIncomplete
        }
    } else {
        PackageEvidence::SizeMatched
    }
}

fn header_evidence(audit: Option<&PackageAudit>) -> HeaderEvidence {
    let Some(audit) = audit else {
        return HeaderEvidence::NotChecked;
    };
    if !audit.headers_requested {
        return HeaderEvidence::NotChecked;
    }
    if audit.referenced.is_empty() {
        return HeaderEvidence::NoReferencedContent;
    }
    if audit.header_count(HeaderStatus::TypeMismatch) > 0
        || audit.header_count(HeaderStatus::SizeMismatch) > 0
        || audit.header_count(HeaderStatus::Malformed) > 0
    {
        return HeaderEvidence::Conflict;
    }
    let consistent = audit.header_count(HeaderStatus::Consistent);
    if consistent == audit.referenced.len() {
        HeaderEvidence::AllConsistent
    } else if audit.header_count(HeaderStatus::Unavailable) == audit.referenced.len() {
        HeaderEvidence::Unavailable
    } else if audit.header_count(HeaderStatus::NotComparable) == audit.referenced.len() {
        HeaderEvidence::NotComparable
    } else {
        HeaderEvidence::MixedOrIncomplete
    }
}

pub fn summarize_record(
    record: &TitleRecord,
    collisions: &[VersionCollision],
) -> EvidenceSummary {
    let matched_release = collisions.iter().find(|collision| {
        collision.title_id == record.title_id
            && collision.version == record.version
            && collision.meta_type == record.meta_type
    });
    let release = match matched_release {
        Some(release) if release.conflicting_content => ReleaseEvidence::DuplicateConflictingCnmt,
        Some(_) => ReleaseEvidence::DuplicateSameCnmt,
        None => ReleaseEvidence::UniqueWithinSuppliedDataset,
    };
    let has_build = record.atmosphere_cheat_build_id.is_some();
    let cheat_target = if release == ReleaseEvidence::DuplicateConflictingCnmt {
        CheatTarget::ConflictingRelease
    } else if has_build {
        CheatTarget::UnverifiedCandidateOnly
    } else {
        CheatTarget::MissingBuildId
    };
    EvidenceSummary {
        package: package_evidence(record.package_audit.as_ref()),
        headers: header_evidence(record.package_audit.as_ref()),
        release,
        executable_association: if has_build {
            "user_designated_main_nso_unverified"
        } else {
            "unavailable"
        },
        cheat_target,
        automatic_cheat_match_allowed: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, package::{ContentMatch, HeaderStatus}};

    fn entry(status: MatchStatus, hash: HashStatus, header: HeaderStatus) -> ContentMatch {
        ContentMatch {
            id: "11".repeat(16),
            content_type: "program",
            expected_size: 4096,
            expected_filename: "11.nca".into(),
            package_filename: None,
            package_size: None,
            status,
            expected_sha256: "AB".repeat(32),
            actual_sha256: None,
            hash_status: hash,
            header_status: header,
            header_program_id: None,
            header_content_type: None,
            header_declared_size: None,
        }
    }
    fn audit(entries: Vec<ContentMatch>, hashing: bool, headers: bool) -> PackageAudit {
        PackageAudit {
            package_format: Format::SwitchNsp,
            title_id: "0100123456788000".into(),
            version: "0".into(),
            meta_type: "application".into(),
            package_entries: entries.len(),
            hashing_requested: hashing,
            headers_requested: headers,
            referenced: entries,
            unreferenced_nca: Vec::new(),
            external_evidence: Vec::new(),
        }
    }
    fn record(package_audit: Option<PackageAudit>, build: bool) -> TitleRecord {
        TitleRecord {
            bundle: "fixture".into(),
            title_id: "0100123456788000".into(),
            version: 0,
            meta_type: "application".into(),
            application_group_id: "0100123456788000".into(),
            grouping_basis: "cnmt_title_id_unverified",
            source_sha256: "FF".repeat(32),
            content_count: 1,
            linked_application_id: None,
            display_title: None,
            display_version: None,
            module_build_id: if build {Some("1234".into())} else {None},
            atmosphere_cheat_build_id: if build {Some("1234567890ABCDEF".into())} else {None},
            package_filename: None,
            package_audit,
        }
    }
    fn summarize(audit: Option<PackageAudit>, build: bool) -> EvidenceSummary {
        summarize_record(&record(audit,build), &[])
    }

    #[test]
    fn metadata_only_and_default_size_match_are_different_levels() {
        let none = summarize(None, false);
        assert_eq!(none.package, PackageEvidence::MetadataOnly);
        assert_eq!(none.headers, HeaderEvidence::NotChecked);
        assert_eq!(none.cheat_target, CheatTarget::MissingBuildId);
        let sized = audit(vec![entry(MatchStatus::Present,HashStatus::NotChecked,HeaderStatus::NotChecked)],false,false);
        assert_eq!(summarize(Some(sized),false).package,PackageEvidence::SizeMatched);
    }

    #[test]
    fn content_hash_match_stays_only_a_candidate_for_cheat_linking() {
        let a = audit(vec![entry(MatchStatus::Present,HashStatus::Matched,HeaderStatus::Consistent)],true,true);
        let summary = summarize(Some(a),true);
        assert_eq!(summary.package,PackageEvidence::HashMatchedToSuppliedCnmt);
        assert_eq!(summary.headers,HeaderEvidence::AllConsistent);
        assert_eq!(summary.cheat_target,CheatTarget::UnverifiedCandidateOnly);
        assert!(!summary.automatic_cheat_match_allowed);
        assert_eq!(summary.executable_association,"user_designated_main_nso_unverified");
    }

    #[test]
    fn digest_mismatch_takes_precedence_over_missing_entries() {
        let a = audit(vec![
            entry(MatchStatus::Present,HashStatus::Mismatched,HeaderStatus::NotChecked),
            entry(MatchStatus::Missing,HashStatus::Unavailable,HeaderStatus::NotChecked),
        ],true,false);
        assert_eq!(summarize(Some(a),true).package,PackageEvidence::HashMismatched);
    }

    #[test]
    fn incomplete_and_unavailable_hashes_never_claim_hash_match() {
        let a = audit(vec![entry(MatchStatus::Missing,HashStatus::Unavailable,HeaderStatus::Unavailable)],true,true);
        let summary = summarize(Some(a),false);
        assert_eq!(summary.package,PackageEvidence::Incomplete);
        assert_eq!(summary.headers,HeaderEvidence::Unavailable);
        let empty = audit(Vec::new(),true,true);
        assert_eq!(summarize(Some(empty.clone()),false).package,PackageEvidence::NoReferencedContent);
        assert_eq!(summarize(Some(empty),false).headers,HeaderEvidence::NoReferencedContent);
    }

    #[test]
    fn header_conflict_is_independent_of_hash_match() {
        let a=audit(vec![entry(MatchStatus::Present,HashStatus::Matched,HeaderStatus::TypeMismatch)],true,true);
        let summary=summarize(Some(a),false);
        assert_eq!(summary.package,PackageEvidence::HashMatchedToSuppliedCnmt);
        assert_eq!(summary.headers,HeaderEvidence::Conflict);
    }

    #[test]
    fn release_collision_is_not_silently_resolved() {
        let duplicate=VersionCollision {
            title_id:"0100123456788000".into(),version:0,meta_type:"application".into(),
            bundles:vec!["a".into(),"b".into()],conflicting_content:false,
        };
        let same=summarize_record(&record(None,true),std::slice::from_ref(&duplicate));
        assert_eq!(same.release,ReleaseEvidence::DuplicateSameCnmt);
        assert_eq!(same.cheat_target,CheatTarget::UnverifiedCandidateOnly);
        let conflicting=VersionCollision{conflicting_content:true,..duplicate};
        let clash=summarize_record(&record(None,true),&[conflicting]);
        assert_eq!(clash.release,ReleaseEvidence::DuplicateConflictingCnmt);
        assert_eq!(clash.cheat_target,CheatTarget::ConflictingRelease);
        assert!(!clash.automatic_cheat_match_allowed);
    }

    #[test]
    fn cannot_read_and_cannot_compare_are_distinct_header_states() {
        let non_comparable = audit(vec![entry(
            MatchStatus::Present, HashStatus::NotChecked, HeaderStatus::NotComparable
        )], false, true);
        assert_eq!(summarize(Some(non_comparable), false).headers, HeaderEvidence::NotComparable);
        let mixed = audit(vec![
            entry(MatchStatus::Present, HashStatus::NotChecked, HeaderStatus::Unavailable),
            entry(MatchStatus::Present, HashStatus::NotChecked, HeaderStatus::NotComparable),
        ], false, true);
        assert_eq!(summarize(Some(mixed), false).headers, HeaderEvidence::MixedOrIncomplete);
    }

    #[test]
    fn mixed_headers_not_all_consistent() {
        let a=audit(vec![
            entry(MatchStatus::Present,HashStatus::NotChecked,HeaderStatus::Consistent),
            entry(MatchStatus::Present,HashStatus::NotChecked,HeaderStatus::Unavailable),
        ],false,true);
        assert_eq!(summarize(Some(a),false).headers,HeaderEvidence::MixedOrIncomplete);
    }
}
