//! In-memory, read-only `Fs` with the semantics of the real `lstat(2)` / `opendir(3)` that the
//! safety guard and the scanner depend on:
//!
//! * the **final** path component is never followed by `lstat` (a symlink is reported as
//!   `Symlink`, even if dangling or looping); `read_dir` **does** follow a final symlink, exactly
//!   like `opendir`, so a scanner that lists a link is visibly wrong (it shows up in
//!   [`FakeFs::read_dir_calls`] and in the bytes it counts);
//! * **intermediate** symlinks are followed (relative targets resolve against the link's
//!   directory), so `root/link/secret` reaches the link target exactly as the kernel would;
//! * more than 40 hops yields `ELOOP` (raw os error 62 on macOS);
//! * a missing component yields `ENOENT`, a non-directory intermediate yields `ENOTDIR`;
//! * `st_dev` is inherited from the nearest ancestor-or-self that was given an explicit device
//!   (a "mount point"), default [`FakeFs::DEFAULT_DEV`];
//! * every node has an inode number, a logical length, allocated 512-byte blocks (so a sparse file
//!   has `blocks * 512 < len`), an `mtime` and a link count; hardlinks share the inode number;
//! * errors are injectable per path: [`FakeFsBuilder::error_at`] fails `lstat`/resolution (an
//!   `ENOENT` on a *listed* entry models a file that vanished after the listing),
//!   [`FakeFsBuilder::list_error_at`] fails only `read_dir` of a directory (macOS TCC: `lstat`
//!   works, `opendir` is `EPERM`).
//!
//! Builder paths are *physical* (no symlinks in the path you pass to `dir`/`file`/`symlink`);
//! missing ancestors are created as directories. The fake has no mutating `Fs` methods; tests
//! change the world between calls through [`FakeFs::replace_with_symlink`] /
//! [`FakeFs::replace_with_dir`] (TOCTOU scenarios, AC-001-9) and inspect [`FakeFs::calls`],
//! [`FakeFs::read_dir_calls`] and [`FakeFs::snapshot`].
//!
//! Scale: lookups take a fast path (one map lookup) while the fake contains no symlink and no
//! injected error, so a chain 10 000 directories deep ([`FakeFsBuilder::deep_dirs`]) is cheap. For
//! such tests switch call logging off ([`FakeFsBuilder::record_calls`]); it stores every path.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cleaner_core::ports::{DirEntry, FileKind, Fs, Metadata};

const ENOENT: i32 = 2;
const ENOTDIR: i32 = 20;
const ELOOP: i32 = 62;
const MAX_HOPS: u32 = 40;
/// First inode number handed out (0 is never a valid inode).
const FIRST_INO: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink(PathBuf),
    Other,
}

/// `lstat` data of one node (kind-independent).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attrs {
    len: u64,
    blocks: u64,
    ino: u64,
    nlink: u32,
    mtime: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    kind: Kind,
    attrs: Attrs,
}

/// Map key of a node: the clean absolute path as raw bytes. Byte keys make lookups `memcmp`-fast
/// (a `PathBuf` key compares component-wise, which is O(depth) per comparison and makes a
/// 10 000-level chain take seconds).
type Key = Vec<u8>;

/// The key of `path`: its bytes when it is already clean (no `//`, `/./`, trailing `/`), otherwise
/// the bytes of its normalized components.
fn key_of(path: &Path) -> Key {
    let bytes = path.as_os_str().as_bytes();
    let clean = bytes.first() == Some(&b'/')
        && path.to_str().is_some_and(|s| {
            !s.contains("//")
                && !s.contains("/./")
                && !s.ends_with("/.")
                && (s == "/" || !s.ends_with('/'))
        });
    if clean {
        return bytes.to_vec();
    }
    let mut key = Key::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => {
                key.push(b'/');
                key.extend_from_slice(n.as_bytes());
            }
            Component::ParentDir => key.extend_from_slice(b"/.."),
            _ => {}
        }
    }
    if key.is_empty() {
        key.push(b'/');
    }
    key
}

/// The key of the child `name` of the directory with key `dir`.
fn child_key(dir: &[u8], name: &OsString) -> Key {
    let mut key = dir.to_vec();
    if dir != b"/" {
        key.push(b'/');
    }
    key.extend_from_slice(name.as_bytes());
    key
}

/// True when `key` is `root` itself or lies below it (component-wise on `/` boundaries).
fn is_under(key: &[u8], root: &[u8]) -> bool {
    key == root || (key.starts_with(root) && (root == b"/" || key.get(root.len()) == Some(&b'/')))
}

#[derive(Debug)]
struct State {
    nodes: BTreeMap<Key, Node>,
    /// Directory key -> names of its direct children (kept in sync with `nodes`).
    children: BTreeMap<Key, BTreeSet<OsString>>,
    devs: BTreeMap<PathBuf, u64>,
    errors: BTreeMap<PathBuf, i32>,
    list_errors: BTreeMap<PathBuf, i32>,
    calls: Vec<PathBuf>,
    list_calls: Vec<PathBuf>,
    record_calls: bool,
    reverse_listing: bool,
    next_ino: u64,
    /// Number of symlink nodes ever inserted (monotonic): 0 enables the lookup fast path.
    symlinks_ever: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            children: BTreeMap::new(),
            devs: BTreeMap::new(),
            errors: BTreeMap::new(),
            list_errors: BTreeMap::new(),
            calls: Vec::new(),
            list_calls: Vec::new(),
            record_calls: true,
            reverse_listing: false,
            next_ino: FIRST_INO,
            symlinks_ever: 0,
        }
    }
}

impl State {
    fn fresh_attrs(&mut self) -> Attrs {
        let ino = self.next_ino;
        self.next_ino += 1;
        Attrs {
            len: 0,
            blocks: 0,
            ino,
            nlink: 1,
            mtime: UNIX_EPOCH,
        }
    }

    /// Insert `node` at `path`, registering it in its parent's child list.
    fn insert(&mut self, path: &Path, node: Node) {
        self.insert_key(key_of(path), path.file_name().map(OsStr::to_owned), node);
    }

    /// Insert `node` under `key`; `name` is the last component (registered with the parent).
    fn insert_key(&mut self, key: Key, name: Option<OsString>, node: Node) {
        if matches!(node.kind, Kind::Symlink(_)) {
            self.symlinks_ever += 1;
        }
        if let Some(name) = name {
            let parent_len = key.len() - name.len() - usize::from(key.len() > name.len() + 1);
            let parent = key.get(..parent_len).unwrap_or(b"/").to_vec();
            self.children.entry(parent).or_default().insert(name);
        }
        self.nodes.insert(key, node);
    }

    /// Create every missing ancestor of `path` as a directory (stops at the first existing one).
    fn ensure_dirs(&mut self, path: &Path) {
        let mut missing = Vec::new();
        for ancestor in path.ancestors().skip(1) {
            if self.nodes.contains_key(&key_of(ancestor)) {
                break;
            }
            missing.push(ancestor.to_path_buf());
        }
        for dir in missing.into_iter().rev() {
            let attrs = self.fresh_attrs();
            self.insert(
                &dir,
                Node {
                    kind: Kind::Dir,
                    attrs,
                },
            );
        }
    }
}

/// In-memory read-only filesystem. See the module docs for the exact semantics.
#[derive(Debug)]
pub struct FakeFs {
    state: Mutex<State>,
}

/// Fluent builder for [`FakeFs`]; start with [`FakeFs::builder`].
#[derive(Debug)]
pub struct FakeFsBuilder {
    state: State,
}

/// Directory component used by [`FakeFsBuilder::deep_dirs`] / [`deep_path`].
const DEEP_NAME: &str = "d";

/// The path [`FakeFsBuilder::deep_dirs`] creates: `base/d/d/.../d` with `depth` components `d`.
#[must_use]
pub fn deep_path(base: impl AsRef<Path>, depth: usize) -> PathBuf {
    let mut p = base.as_ref().to_path_buf();
    for _ in 0..depth {
        p.push(DEEP_NAME);
    }
    p
}

impl FakeFsBuilder {
    fn put(mut self, path: impl AsRef<Path>, kind: Kind) -> Self {
        let path = path.as_ref().to_path_buf();
        self.state.ensure_dirs(&path);
        let attrs = self.state.fresh_attrs();
        self.state.insert(&path, Node { kind, attrs });
        self
    }

    fn node_mut(&mut self, path: &Path) -> &mut Node {
        self.state.nodes.get_mut(&key_of(path)).unwrap_or_else(|| {
            panic!(
                "FakeFsBuilder: no node at {} (create it first)",
                path.display()
            )
        })
    }

    /// A directory (and any missing ancestors).
    #[must_use]
    pub fn dir(self, path: impl AsRef<Path>) -> Self {
        self.put(path, Kind::Dir)
    }

    /// A regular file (and any missing ancestor directories): zero bytes, zero blocks, `mtime`
    /// at the Unix epoch, one link, a fresh inode.
    #[must_use]
    pub fn file(self, path: impl AsRef<Path>) -> Self {
        self.put(path, Kind::File)
    }

    /// A regular file with logical length `len` and `blocks` allocated 512-byte blocks
    /// (`blocks * 512 < len` models a sparse file).
    #[must_use]
    pub fn file_sized(self, path: impl AsRef<Path>, len: u64, blocks: u64) -> Self {
        let p = path.as_ref().to_path_buf();
        self.file(&p).size(p, len, blocks)
    }

    /// A symlink at `path` pointing at `target` (absolute, or relative to `path`'s directory).
    /// The target need not exist (dangling) and may point back at the link (loop).
    #[must_use]
    pub fn symlink(self, path: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        self.put(path, Kind::Symlink(target.as_ref().to_path_buf()))
    }

    /// A node that is none of file/dir/symlink (e.g. a socket).
    #[must_use]
    pub fn other(self, path: impl AsRef<Path>) -> Self {
        self.put(path, Kind::Other)
    }

    /// Set the logical length and allocated 512-byte blocks of the **existing** node at `path`
    /// (any kind: a symlink has its own `lstat` allocation).
    ///
    /// # Panics
    /// If there is no node at `path`.
    #[must_use]
    pub fn size(mut self, path: impl AsRef<Path>, len: u64, blocks: u64) -> Self {
        let node = self.node_mut(path.as_ref());
        node.attrs.len = len;
        node.attrs.blocks = blocks;
        self
    }

    /// Set the modification time (seconds relative to the Unix epoch, may be negative) of the
    /// **existing** node at `path`.
    ///
    /// # Panics
    /// If there is no node at `path`.
    #[must_use]
    pub fn mtime_secs(mut self, path: impl AsRef<Path>, secs: i64) -> Self {
        let magnitude = std::time::Duration::from_secs(secs.unsigned_abs());
        let t = if secs >= 0 {
            UNIX_EPOCH + magnitude
        } else {
            UNIX_EPOCH - magnitude
        };
        self.node_mut(path.as_ref()).attrs.mtime = t;
        self
    }

    /// A second name for the file at `existing`: a new node with the **same inode number, length,
    /// blocks and mtime** (copied now: configure `existing` first). The link count of both names
    /// is the number of names that share the inode.
    ///
    /// # Panics
    /// If there is no node at `existing`.
    #[must_use]
    pub fn hardlink(mut self, new: impl AsRef<Path>, existing: impl AsRef<Path>) -> Self {
        let attrs = self.node_mut(existing.as_ref()).attrs.clone();
        let new = new.as_ref().to_path_buf();
        self.state.ensure_dirs(&new);
        let nlink = attrs.nlink + 1;
        for node in self.state.nodes.values_mut() {
            if node.kind == Kind::File && node.attrs.ino == attrs.ino {
                node.attrs.nlink = nlink;
            }
        }
        self.state.insert(
            &new,
            Node {
                kind: Kind::File,
                attrs: Attrs { nlink, ..attrs },
            },
        );
        self
    }

    /// Override the reported inode number and link count of the existing node at `path` (to model
    /// the same inode number on two different devices, which are different files).
    ///
    /// # Panics
    /// If there is no node at `path`.
    #[must_use]
    pub fn ino(mut self, path: impl AsRef<Path>, ino: u64, nlink: u32) -> Self {
        let node = self.node_mut(path.as_ref());
        node.attrs.ino = ino;
        node.attrs.nlink = nlink;
        self
    }

    /// `depth` nested directories `base/d/d/.../d` ([`deep_path`] gives the path of the deepest),
    /// created with one insertion per level (no quadratic work), for stack-depth tests.
    #[must_use]
    pub fn deep_dirs(mut self, base: impl AsRef<Path>, depth: usize) -> Self {
        let base = base.as_ref();
        self.state.ensure_dirs(&base.join(DEEP_NAME));
        let mut key = key_of(base);
        let name = OsString::from(DEEP_NAME);
        for _ in 0..depth {
            key = child_key(&key, &name);
            if !self.state.nodes.contains_key(&key) {
                let attrs = self.state.fresh_attrs();
                self.state.insert_key(
                    key.clone(),
                    Some(name.clone()),
                    Node {
                        kind: Kind::Dir,
                        attrs,
                    },
                );
            }
        }
        self
    }

    /// Give `path` (and, unless overridden deeper, everything below it) device id `dev`.
    #[must_use]
    pub fn dev(mut self, path: impl AsRef<Path>, dev: u64) -> Self {
        self.state.devs.insert(path.as_ref().to_path_buf(), dev);
        self
    }

    /// Make resolving `path` (as final *or* intermediate component) fail with raw os error
    /// `errno`, e.g. 13 `EACCES`, 63 `ENAMETOOLONG`, 5 `EIO`. If the node exists it is still
    /// listed by its parent's `read_dir`: `errno == 2` models a file that vanished after listing.
    #[must_use]
    pub fn error_at(mut self, path: impl AsRef<Path>, errno: i32) -> Self {
        self.state.errors.insert(path.as_ref().to_path_buf(), errno);
        self
    }

    /// Make `read_dir` of the directory `path` fail with raw os error `errno` while `lstat` of the
    /// directory still works (e.g. 1 `EPERM` for a TCC-protected directory).
    #[must_use]
    pub fn list_error_at(mut self, path: impl AsRef<Path>, errno: i32) -> Self {
        self.state
            .list_errors
            .insert(path.as_ref().to_path_buf(), errno);
        self
    }

    /// Return directory entries in **reverse** name order instead of ascending (the real OS order
    /// is unspecified; results must not depend on it).
    #[must_use]
    pub fn reverse_read_dir(mut self) -> Self {
        self.state.reverse_listing = true;
        self
    }

    /// Switch call logging ([`FakeFs::calls`], [`FakeFs::read_dir_calls`]) on (default) or off.
    #[must_use]
    pub fn record_calls(mut self, on: bool) -> Self {
        self.state.record_calls = on;
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(mut self) -> FakeFs {
        if !self.state.nodes.contains_key(b"/".as_slice()) {
            let attrs = self.state.fresh_attrs();
            self.state.insert(
                Path::new("/"),
                Node {
                    kind: Kind::Dir,
                    attrs,
                },
            );
        }
        FakeFs {
            state: Mutex::new(self.state),
        }
    }
}

impl FakeFs {
    /// Device id of every node without an explicit [`FakeFsBuilder::dev`] ancestor.
    pub const DEFAULT_DEV: u64 = 1;

    /// Start building a fake whose only node is the root directory `/`.
    #[must_use]
    pub fn builder() -> FakeFsBuilder {
        FakeFsBuilder {
            state: State::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("fake fs lock")
    }

    /// Replace whatever is at `path` (and everything below it) with a symlink to `target`.
    /// Simulates an attacker swapping a directory for a link between two calls (TOCTOU).
    pub fn replace_with_symlink(&self, path: impl AsRef<Path>, target: impl AsRef<Path>) {
        let path = path.as_ref();
        let mut st = self.lock();
        Self::remove_subtree(&mut st, path);
        let attrs = st.fresh_attrs();
        st.insert(
            path,
            Node {
                kind: Kind::Symlink(target.as_ref().to_path_buf()),
                attrs,
            },
        );
    }

    /// Replace whatever is at `path` (and everything below it) with an empty directory.
    pub fn replace_with_dir(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        let mut st = self.lock();
        Self::remove_subtree(&mut st, path);
        let attrs = st.fresh_attrs();
        st.insert(
            path,
            Node {
                kind: Kind::Dir,
                attrs,
            },
        );
    }

    fn remove_subtree(st: &mut State, path: &Path) {
        let root = key_of(path);
        st.nodes.retain(|k, _| !is_under(k, &root));
        st.children.retain(|k, _| !is_under(k, &root));
    }

    /// Every path passed to `lstat`, in call order, exactly as the caller supplied it. An empty
    /// list proves a verdict was reached without touching the filesystem.
    #[must_use]
    pub fn calls(&self) -> Vec<PathBuf> {
        self.lock().calls.clone()
    }

    /// Every path passed to `read_dir`, in call order, exactly as the caller supplied it.
    #[must_use]
    pub fn read_dir_calls(&self) -> Vec<PathBuf> {
        self.lock().list_calls.clone()
    }

    /// A deterministic text rendering of every node (path, kind, attributes, device), sorted by
    /// path. Two equal snapshots mean the tree is byte-for-byte unchanged, mtimes included
    /// (INV-01 read-only checks).
    #[must_use]
    pub fn snapshot(&self) -> String {
        use std::fmt::Write as _;
        let st = self.lock();
        let mut out = String::new();
        for (key, node) in &st.nodes {
            let path = PathBuf::from(OsString::from_vec(key.clone()));
            let _ = writeln!(
                out,
                "{} {:?} {:?} dev={}",
                path.display(),
                node.kind,
                node.attrs,
                Self::effective_dev(&st, &path)
            );
        }
        out
    }

    fn effective_dev(st: &State, resolved: &Path) -> u64 {
        if st.devs.is_empty() {
            return Self::DEFAULT_DEV;
        }
        resolved
            .ancestors()
            .find_map(|a| st.devs.get(a).copied())
            .unwrap_or(Self::DEFAULT_DEV)
    }

    /// Fast path: with no symlink and no injected error anywhere, an absolute path without `..`
    /// is just a map lookup. A miss falls through to the faithful slow path (for the error kind).
    fn resolve(st: &State, path: &Path) -> io::Result<(PathBuf, Node)> {
        // `to_str` + `contains("..")` is a cheap conservative test for "no `..` component"
        // (a name like `a..b` merely takes the slow path); `components()` would be O(depth) per call.
        let simple = st.symlinks_ever == 0
            && st.errors.is_empty()
            && path.is_absolute()
            && path.to_str().is_some_and(|s| {
                !s.contains("..") && !s.contains("//") && !s.contains("/./") && !s.ends_with('/')
            });
        if simple && let Some(node) = st.nodes.get(path.as_os_str().as_bytes()) {
            return Ok((path.to_path_buf(), node.clone()));
        }
        Self::resolve_slow(st, path)
    }

    fn resolve_slow(st: &State, path: &Path) -> io::Result<(PathBuf, Node)> {
        let mut queue: VecDeque<OsString> = VecDeque::new();
        for c in path.components() {
            match c {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(n) => queue.push_back(n.to_owned()),
                Component::ParentDir => queue.push_back(OsString::from("..")),
                Component::Prefix(_) => return Err(io::Error::from_raw_os_error(ENOENT)),
            }
        }
        if !path.is_absolute() {
            return Err(io::Error::from_raw_os_error(ENOENT));
        }
        let mut cur = PathBuf::from("/");
        let mut hops = 0;
        if let Some(errno) = st.errors.get(&cur) {
            return Err(io::Error::from_raw_os_error(*errno));
        }
        let root = st
            .nodes
            .get(&key_of(&cur))
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(ENOENT))?;
        let mut last = root;
        while let Some(comp) = queue.pop_front() {
            if comp == ".." {
                cur.pop();
                last = st
                    .nodes
                    .get(&key_of(&cur))
                    .cloned()
                    .ok_or_else(|| io::Error::from_raw_os_error(ENOENT))?;
                continue;
            }
            let next = cur.join(&comp);
            if let Some(errno) = st.errors.get(&next) {
                return Err(io::Error::from_raw_os_error(*errno));
            }
            let node = st
                .nodes
                .get(&key_of(&next))
                .cloned()
                .ok_or_else(|| io::Error::from_raw_os_error(ENOENT))?;
            if queue.is_empty() {
                return Ok((next, node));
            }
            match &node.kind {
                Kind::Dir => cur = next,
                Kind::Symlink(target) => {
                    hops += 1;
                    if hops > MAX_HOPS {
                        return Err(io::Error::from_raw_os_error(ELOOP));
                    }
                    if target.is_absolute() {
                        cur = PathBuf::from("/");
                    }
                    for c in target.components().rev() {
                        match c {
                            Component::Normal(n) => queue.push_front(n.to_owned()),
                            Component::ParentDir => queue.push_front(OsString::from("..")),
                            _ => {}
                        }
                    }
                }
                Kind::File | Kind::Other => {
                    return Err(io::Error::from_raw_os_error(ENOTDIR));
                }
            }
            last = st
                .nodes
                .get(&key_of(&cur))
                .cloned()
                .ok_or_else(|| io::Error::from_raw_os_error(ENOENT))?;
        }
        Ok((cur, last))
    }

    /// `opendir`-style resolution: like [`Self::resolve`] but a final symlink is followed too.
    fn resolve_following(st: &State, path: &Path) -> io::Result<(PathBuf, Node)> {
        let mut current = path.to_path_buf();
        for _ in 0..=MAX_HOPS {
            let (resolved, node) = Self::resolve(st, &current)?;
            if let Kind::Symlink(target) = &node.kind {
                current = if target.is_absolute() {
                    target.clone()
                } else {
                    resolved
                        .parent()
                        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
                        .join(target)
                };
                continue;
            }
            return Ok((resolved, node));
        }
        Err(io::Error::from_raw_os_error(ELOOP))
    }

    fn file_kind(kind: &Kind) -> FileKind {
        match kind {
            Kind::File => FileKind::File,
            Kind::Dir => FileKind::Dir,
            Kind::Symlink(_) => FileKind::Symlink,
            Kind::Other => FileKind::Other,
        }
    }
}

impl Fs for FakeFs {
    fn lstat(&self, path: &Path) -> io::Result<Metadata> {
        let mut st = self.lock();
        if st.record_calls {
            st.calls.push(path.to_path_buf());
        }
        let (resolved, node) = Self::resolve(&st, path)?;
        Ok(Metadata {
            kind: Self::file_kind(&node.kind),
            dev: Self::effective_dev(&st, &resolved),
            ino: node.attrs.ino,
            blocks: node.attrs.blocks,
            len: node.attrs.len,
            mtime: node.attrs.mtime,
            nlink: node.attrs.nlink,
        })
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let mut st = self.lock();
        if st.record_calls {
            st.list_calls.push(path.to_path_buf());
        }
        let (resolved, node) = Self::resolve_following(&st, path)?;
        if let Some(errno) = st.list_errors.get(&resolved) {
            return Err(io::Error::from_raw_os_error(*errno));
        }
        if node.kind != Kind::Dir {
            return Err(io::Error::from_raw_os_error(ENOTDIR));
        }
        let dir_key = key_of(&resolved);
        let mut entries: Vec<DirEntry> = st
            .children
            .get(&dir_key)
            .into_iter()
            .flatten()
            .filter_map(|name| {
                let child = st.nodes.get(&child_key(&dir_key, name))?;
                Some(DirEntry {
                    name: name.clone(),
                    kind: Self::file_kind(&child.kind),
                })
            })
            .collect();
        if st.reverse_listing {
            entries.reverse();
        }
        Ok(entries)
    }
}
