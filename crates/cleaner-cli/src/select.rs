//! Rule selectors for `cleaner scan` (AC-002-14).

use std::fmt;

use cleaner_core::rules::{Rule, Tier};

/// Why a selector combination was refused (the CLI maps every variant to exit code 2 and prints
/// the message, creating nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// `--rule <id>` named a rule that does not exist; `valid` lists every built-in id.
    UnknownRule {
        /// The offending id as typed.
        id: String,
        /// All valid ids, in rule order.
        valid: Vec<String>,
    },
    /// The selectors are valid but together match no rule (e.g. `--rule user-caches --tier caution`).
    NoMatch,
}

impl fmt::Display for SelectError {
    /// `UnknownRule`: names the offending id and lists **every** valid id; `NoMatch`: says no rule
    /// matches the selectors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRule { id, valid } => {
                write!(f, "unknown rule `{id}`; valid rules: {}", valid.join(", "))
            }
            Self::NoMatch => f.write_str("no rule matches the --rule and --tier selectors given"),
        }
    }
}

impl std::error::Error for SelectError {}

/// Apply the selectors to the rule table.
///
/// Contract (AC-002-14): no `ids` and no `tier` -> every rule; `ids` -> only those rules; `tier`
/// -> only rules of that tier; both -> the **intersection** (selectors only narrow). The result is
/// always in `all`'s order (rule order matters for hardlink attribution), whatever the order or
/// repetition of `ids`. Ids match exactly (case-sensitive). An id that is not in `all` is
/// `UnknownRule` (checked before the intersection); a valid combination that matches nothing is
/// `NoMatch`. Pure; nothing is marked selected or recommended.
///
/// # Errors
/// [`SelectError`] as described above.
pub fn select_rules(
    all: Vec<Rule>,
    ids: &[String],
    tier: Option<Tier>,
) -> Result<Vec<Rule>, SelectError> {
    if let Some(unknown) = ids.iter().find(|id| all.iter().all(|rule| rule.id != **id)) {
        return Err(SelectError::UnknownRule {
            id: unknown.clone(),
            valid: all.iter().map(|rule| rule.id.clone()).collect(),
        });
    }
    let selected: Vec<Rule> = all
        .into_iter()
        .filter(|rule| ids.is_empty() || ids.contains(&rule.id))
        .filter(|rule| tier.is_none_or(|t| rule.tier == t))
        .collect();
    if selected.is_empty() {
        Err(SelectError::NoMatch)
    } else {
        Ok(selected)
    }
}
