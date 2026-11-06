//! `SafetyGuard`: decides what may ever be touched (INV-06, INV-07, INV-08, INV-13).
//!
//! # Contract (spec 001 AC-001-1 .. AC-001-10)
//! * Verdict precedence for `admit`: syntax (`NotAbsolute`, `Traversal`) -> deny list
//!   (`DenyListed`, `AncestorOfDenied`) -> containment (`OutsideRoot`) -> filesystem checks
//!   (`SymlinkEscape`, `CrossDevice`, `Io`). All verdicts before the filesystem checks are lexical
//!   and must not call the [`Fs`] port at all.
//! * `admit` never caches: every call re-resolves through the [`Fs`] port (TOCTOU, AC-001-9).
//! * `admit` does **not** validate the root's own deny-list status; `admit_root` does.
//! * The guard never canonicalizes and never follows a link: it walks root -> candidate one prefix
//!   at a time with `lstat` ([`Fs::lstat`]) and refuses a symlink in any non-final position.
//! * Deny-list matching is on path *components* (never string prefixes), compared through a
//!   folded key (NFC, then lowercase) because default APFS volumes are case- and
//!   normalization-insensitive (AC-001-17). Containment stays exact and case-sensitive, so
//!   folding can only ever refuse more, never admit something.
//!
//! The built-in deny list is code, not configuration (INV-06): [`SafetyGuard::with_extra_denied`]
//! can only add entries.

use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path, PathBuf};

use unicode_normalization::UnicodeNormalization as _;

use crate::ports::{FileKind, Fs};

/// The macOS firmlink prefix under which the data volume is also reachable (`/System/Volumes/Data/Users/..`
/// is the same directory as `/Users/..`).
const FIRMLINK_PREFIX: [&str; 3] = ["System", "Volumes", "Data"];

/// `/var`, `/etc` and `/tmp` are symlinks to `/private/{var,etc,tmp}` (AC-001-18).
const PRIVATE_ALIASES: [&str; 3] = ["var", "etc", "tmp"];

/// Entries of the INV-06 deny list that do not depend on the home directory, as components below `/`.
const FIXED_DENIED: [&str; 6] = [
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/private/var/db",
    "/Library/Apple",
];

/// Entries of the INV-06 deny list relative to `$HOME`.
const HOME_DENIED: [&str; 8] = [
    "Documents",
    "Desktop",
    "Pictures",
    "Library/Keychains",
    "Library/Mobile Documents",
    "Library/Messages",
    ".ssh",
    ".gnupg",
];

/// Injected absolute home directory. `core` never reads `$HOME` (ADR 0001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeDir(PathBuf);

impl HomeDir {
    /// Wrap an absolute home path supplied by the composition root.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The wrapped path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// Stable cause of a refusal (used in audit logs and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedKind {
    /// Empty or relative path.
    NotAbsolute,
    /// Contains a `..` component.
    Traversal,
    /// Equal to, or below, a deny-listed path.
    DenyListed,
    /// Would contain a deny-listed path (deleting it would delete the denied descendant).
    AncestorOfDenied,
    /// Not strictly below the rule root (component-wise), or equal to the root.
    OutsideRoot,
    /// The root, or a parent component between root and candidate, is a symlink.
    SymlinkEscape,
    /// Candidate (or its parent) is on a different device than the root.
    CrossDevice,
    /// Any `Fs` error while resolving (fail closed, INV-13).
    Io,
}

/// A refusal: the cause and the argument that was refused (candidate, or root for `admit_root`),
/// exactly as passed by the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("path refused ({kind:?}): {path:?}")]
pub struct Denied {
    /// Why.
    pub kind: DeniedKind,
    /// The refused argument as passed in.
    pub path: PathBuf,
}

/// A path that passed [`SafetyGuard::admit`]; the only type later phases accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePath {
    path: PathBuf,
    is_symlink: bool,
    exists: bool,
}

impl SafePath {
    /// The normalized absolute path (firmlink prefix stripped, leading `/var|etc|tmp` rewritten to
    /// `/private/..`, `//` and `/./` collapsed). The caller's letter case is kept.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when the final component is itself a symlink (it may be removed as a link, never
    /// traversed).
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.is_symlink
    }

    /// False only for a root admitted by [`SafetyGuard::admit_root`] that does not exist (an
    /// absent rule root is not unsafe; spec 001 AC-001-5 amendment). Always true for `admit`.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.exists
    }
}

/// Applies the two leading-component alias rules to `parts` (the components below `/` of an
/// absolute path) and returns the remaining components plus whether `private` must be put in
/// front: first every leading `System/Volumes/Data` firmlink prefix is stripped (repeatedly), then
/// a leading `var`/`etc`/`tmp` becomes `private/var|etc|tmp`. `is(part, word)` decides whether a
/// component equals a (capitalized, as written in the constants) word: exact for [`normalize`],
/// case-folded for deny matching.
fn rewrite_aliases<S: AsRef<OsStr>>(
    mut parts: &[S],
    is: impl Fn(&OsStr, &str) -> bool,
) -> (&[S], bool) {
    while let [a, b, c, tail @ ..] = parts
        && is(a.as_ref(), FIRMLINK_PREFIX[0])
        && is(b.as_ref(), FIRMLINK_PREFIX[1])
        && is(c.as_ref(), FIRMLINK_PREFIX[2])
    {
        parts = tail;
    }
    let private =
        matches!(parts, [first, ..] if PRIVATE_ALIASES.iter().any(|w| is(first.as_ref(), w)));
    (parts, private)
}

/// Lexically normalize: collapse `//`, `/./` and trailing `/`; for absolute paths strip every
/// leading `/System/Volumes/Data` firmlink prefix (repeatedly) and then rewrite a leading `/var`,
/// `/etc` or `/tmp` component to `/private/<it>` (AC-001-3, AC-001-18). Both rewrites are exact
/// and case-sensitive, only apply to the *leading* components (`/variable`, `/tmpx`,
/// `/Users/u/var` are unchanged) and the function is idempotent. `..` components are preserved
/// (rejecting them is `admit`'s job). Pure; no filesystem access.
#[must_use]
pub fn normalize(path: &Path) -> PathBuf {
    let absolute = path.has_root();
    let parts: Vec<&OsStr> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name),
            Component::ParentDir => Some(OsStr::new("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect();
    let (rest, private) = if absolute {
        rewrite_aliases(&parts, |part, word| part == OsStr::new(word))
    } else {
        (parts.as_slice(), false)
    };
    let mut out = PathBuf::new();
    if absolute {
        out.push("/");
    }
    if private {
        out.push("private");
    }
    out.extend(rest);
    out
}

/// Folded component: Unicode NFC, then lowercase. Components that are not valid UTF-8 are folded
/// through their lossy form (invalid bytes become U+FFFD), so distinct non-UTF-8 names can share a
/// key: this can only make deny matching over-block, never under-block, which is the intended
/// direction (AC-001-17).
fn fold(name: &OsStr) -> String {
    name.to_string_lossy()
        .nfc()
        .collect::<String>()
        .to_lowercase()
}

/// Comparison key of an absolute path for deny-list matching: the normalized components, folded,
/// with the firmlink and `/private` alias rules applied again on the folded form (so
/// `/SYSTEM/VOLUMES/DATA/...` and `/VAR/db` alias as well). Used for matching only; never for
/// containment and never returned to callers.
fn deny_key(path: &Path) -> Vec<String> {
    let folded: Vec<String> = normalize(path)
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(fold(name)),
            _ => None,
        })
        .collect();
    let (rest, private) = rewrite_aliases(&folded, |part, word| {
        part.to_str() == Some(word.to_lowercase().as_str())
    });
    private
        .then(|| "private".to_owned())
        .into_iter()
        .chain(rest.iter().cloned())
        .collect()
}

/// Syntax gate shared by all entry points: the path must be absolute and free of `..`.
fn check_syntax(path: &Path) -> Result<(), DeniedKind> {
    if !path.is_absolute() {
        return Err(DeniedKind::NotAbsolute);
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(DeniedKind::Traversal);
    }
    Ok(())
}

/// The path-safety decision point.
///
/// Holds only the (normalized) deny list; it caches nothing about the filesystem, so every
/// [`SafetyGuard::admit`] re-resolves through the [`Fs`] port (AC-001-9).
#[derive(Debug, Clone)]
pub struct SafetyGuard {
    /// Folded keys (see [`deny_key`]) of the built-in and extra deny entries.
    denied: Vec<Vec<String>>,
}

impl SafetyGuard {
    /// Build a guard whose built-in deny list (INV-06) is expanded from `home`.
    ///
    /// The list: `/System`, `/usr`, `/bin`, `/sbin`, `/private/var/db`, `/Library/Apple` and, below
    /// `home`: `Documents`, `Desktop`, `Pictures`, `Library/Keychains`, `Library/Mobile Documents`,
    /// `Library/Messages`, `.ssh`, `.gnupg`. `/` and `home` themselves are denied as ancestors.
    /// (The INV-06 `/usr/local` carve-out is deferred: phase 1 denies all of `/usr`.)
    #[must_use]
    pub fn new(home: &HomeDir) -> Self {
        let home = normalize(home.path());
        let denied = FIXED_DENIED
            .iter()
            .map(PathBuf::from)
            .chain(HOME_DENIED.iter().map(|rel| home.join(rel)))
            .map(|entry| deny_key(&entry))
            .collect();
        Self { denied }
    }

    /// Add user-configured deny entries; they are matched exactly like built-in ones (normalized,
    /// case- and Unicode-normalization-insensitive). The built-in entries always remain denied;
    /// there is deliberately no API to remove or override one (AC-001-8). An entry that is not
    /// absolute can never match a (necessarily absolute) candidate and is ignored.
    #[must_use]
    pub fn with_extra_denied(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.denied.extend(
            paths
                .into_iter()
                .filter(|p| p.is_absolute())
                .map(|p| deny_key(&p)),
        );
        self
    }

    /// The deny-list verdict for an absolute path, on folded keys: denied itself or below a denied
    /// entry, or an ancestor of one (removing it would remove the denied descendant). Component-wise,
    /// so `Documents-old` is not `Documents`.
    fn deny_verdict(&self, path: &Path) -> Option<DeniedKind> {
        let key = deny_key(path);
        if self.denied.iter().any(|d| key.starts_with(d)) {
            Some(DeniedKind::DenyListed)
        } else if self.denied.iter().any(|d| d.starts_with(&key)) {
            Some(DeniedKind::AncestorOfDenied)
        } else {
            None
        }
    }

    /// Admit `candidate` as a deletion candidate strictly below `root`.
    ///
    /// Checks run in this order and the first failure is reported (all but the last group are
    /// lexical and make **zero** [`Fs`] calls):
    /// 1. syntax: `candidate`, then `root`, must be absolute ([`DeniedKind::NotAbsolute`]) and free
    ///    of `..` ([`DeniedKind::Traversal`]); redundant `//`, `/.` and a trailing `/` are
    ///    normalized away, not rejected;
    /// 2. deny list on the normalized candidate ([`DeniedKind::DenyListed`],
    ///    [`DeniedKind::AncestorOfDenied`]); the root's own deny status is **not** judged here
    ///    (see [`SafetyGuard::admit_root`]);
    /// 3. containment: the candidate must be a strict, component-wise descendant of the root
    ///    ([`DeniedKind::OutsideRoot`]); the root itself is never a candidate;
    /// 4. filesystem, via `lstat` only, re-run on every call: the root must not be a symlink and
    ///    no parent component between root and candidate may be one ([`DeniedKind::SymlinkEscape`],
    ///    whatever the link's target); every component must be on the root's device
    ///    ([`DeniedKind::CrossDevice`]); any `lstat` failure, including a missing candidate, is
    ///    [`DeniedKind::Io`] (fail closed, INV-13).
    ///
    /// A symlink as the **final** component is admitted (flagged by [`SafePath::is_symlink`]); it is
    /// never looked into. The returned [`SafePath`] holds the normalized spelling.
    ///
    /// Forbidden effects: any filesystem write; caching a verdict; following a link.
    ///
    /// # Errors
    /// [`Denied`] naming the first failing check; its `path` is `candidate` exactly as passed.
    pub fn admit(&self, fs: &dyn Fs, root: &Path, candidate: &Path) -> Result<SafePath, Denied> {
        let refuse = |kind| Denied {
            kind,
            path: candidate.to_path_buf(),
        };
        check_syntax(candidate).map_err(refuse)?;
        check_syntax(root).map_err(refuse)?;

        let candidate = normalize(candidate);
        let root = normalize(root);
        if let Some(kind) = self.deny_verdict(&candidate) {
            return Err(refuse(kind));
        }
        let below_root = candidate
            .strip_prefix(&root)
            .ok()
            .filter(|rel| rel.components().next().is_some())
            .ok_or_else(|| refuse(DeniedKind::OutsideRoot))?;

        let io_refusal = |_: io::Error| refuse(DeniedKind::Io);
        let root_meta = fs.lstat(&root).map_err(io_refusal)?;
        if root_meta.kind == FileKind::Symlink {
            return Err(refuse(DeniedKind::SymlinkEscape));
        }
        let mut current = root.clone();
        let mut is_symlink = false;
        let mut components = below_root.components().peekable();
        while let Some(component) = components.next() {
            current.push(component);
            let meta = fs.lstat(&current).map_err(io_refusal)?;
            if meta.kind == FileKind::Symlink {
                if components.peek().is_some() {
                    return Err(refuse(DeniedKind::SymlinkEscape));
                }
                is_symlink = true;
            }
            if meta.dev != root_meta.dev {
                return Err(refuse(DeniedKind::CrossDevice));
            }
        }
        Ok(SafePath {
            path: candidate,
            is_symlink,
            exists: true,
        })
    }

    /// Admit `root` itself as a rule root: absolute, free of `..`, not denied, not an ancestor of
    /// a denied path, not a symlink. (`admit` of the root is `OutsideRoot`: a rule never deletes
    /// its own root.)
    ///
    /// Syntax and deny-list verdicts are lexical (zero [`Fs`] calls) and come first, so an absent
    /// but denied root is still refused. Then `lstat` decides: a root that does not exist
    /// (`NotFound`) is `Ok` with [`SafePath::exists`] `== false` (an absent root is not unsafe:
    /// nothing can be touched), a symlink is [`DeniedKind::SymlinkEscape`], and any other error is
    /// [`DeniedKind::Io`]. The returned path is normalized.
    ///
    /// **Callers must pass canonicalized rule roots** (composition-root duty, AC-001-18): the guard
    /// is lexical about everything *above* the root. It rewrites the well-known `/var`, `/etc`,
    /// `/tmp` and firmlink aliases and judges case/Unicode aliases of denied names, but it does not
    /// resolve other symlinks in the root's own ancestors, which `lstat` follows silently.
    ///
    /// # Errors
    /// [`Denied`] as for [`SafetyGuard::admit`]; its `path` is `root` exactly as passed.
    pub fn admit_root(&self, fs: &dyn Fs, root: &Path) -> Result<SafePath, Denied> {
        let refuse = |kind| Denied {
            kind,
            path: root.to_path_buf(),
        };
        check_syntax(root).map_err(refuse)?;
        let root = normalize(root);
        if let Some(kind) = self.deny_verdict(&root) {
            return Err(refuse(kind));
        }
        match fs.lstat(&root) {
            Ok(meta) if meta.kind == FileKind::Symlink => Err(refuse(DeniedKind::SymlinkEscape)),
            Ok(_) => Ok(SafePath {
                path: root,
                is_symlink: false,
                exists: true,
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(SafePath {
                path: root,
                is_symlink: false,
                exists: false,
            }),
            Err(_) => Err(refuse(DeniedKind::Io)),
        }
    }
}
