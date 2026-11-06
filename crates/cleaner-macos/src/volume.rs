//! [`RealVolume`]: the Foundation-backed `VolumeCapacity` adapter (ADR 0002, spec 002 AC-002-1..3).
//!
//! This module holds the **only** `unsafe` block of the whole workspace (ADR 0001, spec 002
//! "Ratified after 002b red phase"): reading the `NSURLVolume*Key` constants, which `objc2` exposes
//! as `extern` statics. Everything else (building the URL, the query, the number extraction) is safe
//! `objc2` API. The block is exercised by `tests/real_volume.rs`.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use cleaner_core::ports::{VolumeCapacity, VolumeCaps, VolumeError};
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{NSArray, NSDictionary, NSNumber, NSString, NSURL, NSURLResourceKey};

/// The Foundation resource keys the query needs, in the order of [`RawCaps`].
struct Keys {
    volume_url: &'static NSURLResourceKey,
    total: &'static NSURLResourceKey,
    available: &'static NSURLResourceKey,
    important: &'static NSURLResourceKey,
    opportunistic: &'static NSURLResourceKey,
}

impl Keys {
    fn load() -> Self {
        // SAFETY: these are immutable `extern` statics (`NSString *const`) defined by Foundation
        // and initialized when the framework is loaded, which linking `objc2-foundation` guarantees
        // before `main`. They are only read (copied as `&'static` references), never written, so
        // there is no data race and no aliasing violation. Covered by `tests/real_volume.rs`.
        unsafe {
            Self {
                volume_url: objc2_foundation::NSURLVolumeURLKey,
                total: objc2_foundation::NSURLVolumeTotalCapacityKey,
                available: objc2_foundation::NSURLVolumeAvailableCapacityKey,
                important: objc2_foundation::NSURLVolumeAvailableCapacityForImportantUsageKey,
                opportunistic:
                    objc2_foundation::NSURLVolumeAvailableCapacityForOpportunisticUsageKey,
            }
        }
    }
}

/// [`VolumeCapacity`] backed by Foundation resource values (ADR 0002, `objc2-foundation`).
///
/// Contract: `query(path)` describes the volume that **holds** `path` (a directory or any other
/// node): `mount_point` is the volume URL path Foundation reports for `path` (an absolute directory; on the
/// Data volume it is the Data volume mount, not necessarily a lexical ancestor, because of firmlinks), `total` is `volumeTotalCapacity`, `available` is
/// `volumeAvailableCapacity`, `available_important` is `...ForImportantUsage`,
/// `available_opportunistic` is `...ForOpportunisticUsage`, all in bytes.
///
/// Errors (never a panic, never a failed value reported as `0`, INV-13): a path that does not exist
/// (including the empty path) is `VolumeError::NotFound{path}` with the path as queried; an OS
/// permission refusal is `PermissionDenied`; anything else (a path with an interior NUL or that is
/// not UTF-8, a name too long, Foundation failing or omitting a value) is `QueryFailed`. The query
/// is read-only.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealVolume;

impl VolumeCapacity for RealVolume {
    fn query(&self, path: &Path) -> Result<VolumeCaps, VolumeError> {
        classify_path(path)?;
        let text = path.to_str().ok_or_else(|| VolumeError::QueryFailed {
            reason: "path is not valid UTF-8".to_owned(),
        })?;
        let keys = Keys::load();
        let wanted: Retained<NSArray<NSURLResourceKey>> = NSArray::from_slice(&[
            keys.volume_url,
            keys.total,
            keys.available,
            keys.important,
            keys.opportunistic,
        ]);
        let url = NSURL::fileURLWithPath(&NSString::from_str(text));
        let values =
            url.resourceValuesForKeys_error(&wanted)
                .map_err(|e| VolumeError::QueryFailed {
                    reason: e.localizedDescription().to_string(),
                })?;
        let number = |key: &NSURLResourceKey| capacity(&values, key);
        let mount = values
            .objectForKey(keys.volume_url)
            .and_then(|url| url.downcast::<NSURL>().ok())
            .and_then(|url| url.path())
            .map(|p| PathBuf::from(p.to_string()))
            .ok_or_else(|| VolumeError::QueryFailed {
                reason: "Foundation reported no volume URL".to_owned(),
            })?;
        Ok(VolumeCaps {
            mount_point: mount,
            total: number(keys.total)?,
            available: number(keys.available)?,
            available_important: number(keys.important)?,
            available_opportunistic: number(keys.opportunistic)?,
        })
    }
}

/// `Ok` when `path` exists (not following a final link), else the typed error for why it cannot be
/// described: `ENOENT` -> `NotFound`, `EACCES`/`EPERM` -> `PermissionDenied`, the rest (`ENAMETOOLONG`,
/// an interior NUL, ...) -> `QueryFailed`.
fn classify_path(path: &Path) -> Result<(), VolumeError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Err(VolumeError::NotFound {
            path: path.to_path_buf(),
        }),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(VolumeError::PermissionDenied),
        Err(e) => Err(VolumeError::QueryFailed {
            reason: e.to_string(),
        }),
    }
}

/// One capacity number of the Foundation dictionary as bytes. A missing, non-numeric or negative
/// value is an error: unknown is never `0` (INV-13).
fn capacity(
    values: &NSDictionary<NSURLResourceKey, AnyObject>,
    key: &NSURLResourceKey,
) -> Result<u64, VolumeError> {
    let fail = |what: &str| VolumeError::QueryFailed {
        reason: format!("Foundation returned {what} for `{key}`"),
    };
    let value = values.objectForKey(key).ok_or_else(|| fail("no value"))?;
    let number = value
        .downcast::<NSNumber>()
        .map_err(|_| fail("a non-number"))?;
    u64::try_from(number.longLongValue()).map_err(|_| fail("a negative number"))
}
