//! Cleanup rules as data (ADR 0001, spec 002 "Built-in rules") and the claim logic that decides
//! which rule owns a path when roots nest (AC-002-9, AC-002-22).
//!
//! All roots and excludes are **relative to `$HOME`** (the scanner joins them with the injected
//! [`HomeDir`](crate::safety::HomeDir)); a rule never contains an absolute path.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

/// Age threshold of `old-downloads` (spec 002 table).
const OLD_DOWNLOADS_DAYS: u64 = 90;
const SECS_PER_DAY: u64 = 86_400;

/// Risk tier of a rule (INV-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Tier {
    /// Regenerable cache or log.
    #[serde(rename = "safe")]
    Safe,
    /// May be user-visible loss.
    #[serde(rename = "caution")]
    Caution,
    /// Listed, never deleted by this tool.
    #[serde(rename = "report-only")]
    ReportOnly,
}

/// One declarative reclaimable category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Stable kebab-case identifier (`user-caches`).
    pub id: String,
    /// Risk tier.
    pub tier: Tier,
    /// Directories to scan, relative to `$HOME` (no leading `/`, no `..`).
    pub roots: Vec<PathBuf>,
    /// Subtrees (relative to `$HOME`) that contribute nothing to this rule and are not claimed by it.
    pub excludes: Vec<PathBuf>,
    /// When set: only **regular files** with `mtime <= now - min_age` count (spec 002 AC-002-12).
    pub min_age: Option<Duration>,
    /// One-sentence human explanation (never empty in the built-in table).
    pub explain: String,
    /// Whether a later phase may ever act on this rule. Always `false` for `Report-only`.
    pub deletable: bool,
}

impl Rule {
    /// A rule with the given id, tier and roots; no excludes, no age filter, a placeholder
    /// explanation, and `deletable` iff the tier is not `Report-only`.
    #[must_use]
    pub fn new(id: &str, tier: Tier, roots: &[&str]) -> Self {
        Self {
            id: id.to_owned(),
            tier,
            roots: roots.iter().map(PathBuf::from).collect(),
            excludes: Vec::new(),
            min_age: None,
            explain: "test rule".to_owned(),
            deletable: tier != Tier::ReportOnly,
        }
    }
}

/// The built-in rule table of spec 002, in the spec's order (that order is the "rule order" used
/// for hardlink attribution).
///
/// Postconditions: twelve rules, ids unique and kebab-case, every `explain` non-empty, every root
/// a clean path relative to `$HOME` that `SafetyGuard::admit_root` accepts, `Report-only` rules
/// not deletable, no root shared by two rules. Changing the table requires a spec amendment.
#[must_use]
pub fn builtin() -> Vec<Rule> {
    let rule = |id: &str, tier: Tier, roots: &[&str], explain: &str| {
        let mut rule = Rule::new(id, tier, roots);
        explain.clone_into(&mut rule.explain);
        rule
    };
    let mut user_logs = rule(
        "user-logs",
        Tier::Safe,
        &["Library/Logs"],
        "Application logs; apps write fresh ones on demand. This tool's own logs are never counted.",
    );
    user_logs.excludes = vec![
        PathBuf::from("Library/Logs/mac-cleaner"),
        PathBuf::from("Library/Logs/mac-cleaner-dev"),
    ];
    let mut old_downloads = rule(
        "old-downloads",
        Tier::Caution,
        &["Downloads"],
        "Files in Downloads not modified for 90 days; you may still want them.",
    );
    old_downloads.min_age = Some(Duration::from_secs(OLD_DOWNLOADS_DAYS * SECS_PER_DAY));
    let ios_backups = rule(
        "ios-backups",
        Tier::ReportOnly,
        &["Library/Application Support/MobileSync/Backup"],
        "iPhone and iPad backups; listed for information only, never deleted by this tool.",
    );

    vec![
        rule(
            "user-caches",
            Tier::Safe,
            &["Library/Caches"],
            "Per-app caches that apps rebuild on demand; more specific rules claim their own subtrees.",
        ),
        rule(
            "homebrew-cache",
            Tier::Safe,
            &["Library/Caches/Homebrew"],
            "Downloaded Homebrew bottles and sources; `brew` downloads them again when needed.",
        ),
        user_logs,
        rule(
            "trash",
            Tier::Safe,
            &[".Trash"],
            "Items already in the Trash; space is only freed once the Trash is emptied.",
        ),
        rule(
            "xcode-derived-data",
            Tier::Safe,
            &["Library/Developer/Xcode/DerivedData"],
            "Xcode build products and indexes; Xcode rebuilds them.",
        ),
        rule(
            "cargo-cache",
            Tier::Safe,
            &[".cargo/registry/cache", ".cargo/registry/src", ".cargo/git"],
            "Downloaded crates and git checkouts; cargo downloads them again when needed.",
        ),
        rule(
            "npm-cache",
            Tier::Safe,
            &[".npm/_cacache"],
            "npm's content-addressed download cache; npm refills it on demand.",
        ),
        rule(
            "xcode-archives",
            Tier::Caution,
            &["Library/Developer/Xcode/Archives"],
            "Xcode archives of built apps; may be the only copy of a shipped build.",
        ),
        rule(
            "ios-device-support",
            Tier::Caution,
            &["Library/Developer/Xcode/iOS DeviceSupport"],
            "Debug symbols Xcode copied from connected devices; re-copied on the next connection.",
        ),
        rule(
            "coresimulator",
            Tier::Caution,
            &["Library/Developer/CoreSimulator/Devices"],
            "Simulator devices with their apps and data; deleting loses simulator state.",
        ),
        old_downloads,
        ios_backups,
    ]
}

/// The rule that **claims** `rel` (a path relative to `$HOME`), or `None`.
///
/// A rule is a candidate when one of its roots is a component-wise prefix of `rel` (equality
/// counts: the root itself is claimed) **and** `rel` is not equal to or below one of that rule's
/// `excludes` (an excluded subtree is not claimed by the excluding rule; an enclosing rule of
/// another root may still claim it). Among the candidates the one with the **longest** matching
/// root (most components) wins; a tie goes to the earlier rule in `rules`. Matching is on path
/// components, never on string prefixes (`Library/Caches` does not claim `Library/Caches-old`).
///
/// Pure; the result does not depend on the order of `rules` except for exact ties.
#[must_use]
pub fn owner_of<'a>(rules: &'a [Rule], rel: &Path) -> Option<&'a Rule> {
    let mut best: Option<(usize, &Rule)> = None;
    for rule in rules {
        if rule.excludes.iter().any(|ex| rel.starts_with(ex)) {
            continue;
        }
        let longest = rule
            .roots
            .iter()
            .filter(|root| rel.starts_with(root))
            .map(|root| root.components().count())
            .max();
        if let Some(depth) = longest
            && best.is_none_or(|(best_depth, _)| depth > best_depth)
        {
            best = Some((depth, rule));
        }
    }
    best.map(|(_, rule)| rule)
}
