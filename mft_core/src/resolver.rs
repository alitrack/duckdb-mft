//! Parent-reference path reconstruction (§A.5).
//!
//! No path is stored on any record — only each record's own name plus a parent
//! entry reference. Reconstruction walks parent links upward, prepending names,
//! until reaching the volume root (entry 5). The walk is **bounded** by a max
//! depth and a visited-set cycle check, so a corrupt or hostile `$MFT` with a
//! parent loop or absurd depth can never spin or overflow — it falls back to a
//! `\$Cycle` / `\$Orphan` sentinel with a diagnostic.

use std::collections::BTreeMap;

use crate::cursor::ResolverNode;

/// The volume root MFT entry (`.`).
pub const ROOT_ENTRY: u64 = 5;

/// Path separator used in reconstructed paths (NTFS convention).
pub const SEP: char = '\\';

/// The outcome of resolving one entry's path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPath {
    pub path: String,
    /// A diagnostic token when the path could not be cleanly resolved
    /// (`orphan-parent`, `cycle`), else `None`.
    pub diagnostic: Option<&'static str>,
}

/// Resolve the full path of `entry` against the `resolver` index, walking
/// parents up to [`ROOT_ENTRY`]. `max_depth` and a visited-set bound the walk.
///
/// - A missing / out-of-range parent → rooted at `\$Orphan\<parent>`,
///   diagnostic `orphan-parent`.
/// - A parent whose **current** sequence differs from the child's recorded
///   `parent_seq` (slot reused, §A.4) → also `orphan-parent`.
/// - A loop or depth breach → `\$Cycle\…`, diagnostic `cycle`.
pub fn resolve(resolver: &BTreeMap<u64, ResolverNode>, entry: u64, max_depth: u16) -> ResolvedPath {
    let Some(node) = resolver.get(&entry) else {
        // No name record for this entry at all.
        return ResolvedPath {
            path: format!("{SEP}$Orphan{SEP}{entry}"),
            diagnostic: Some("orphan-parent"),
        };
    };

    // Root itself.
    if entry == ROOT_ENTRY {
        return ResolvedPath {
            path: node.name.clone(),
            diagnostic: None,
        };
    }

    let mut components: Vec<&str> = vec![node.name.as_str()];
    let mut visited = vec![entry];
    let mut current = node;

    loop {
        let parent_entry = current.parent_entry;

        // Reached the volume root → done.
        if parent_entry == ROOT_ENTRY {
            break;
        }

        // Depth bound or cycle detection → bounded `\$Cycle` fallback.
        if visited.len() >= max_depth as usize || visited.contains(&parent_entry) {
            return cycle_path(&components);
        }

        let Some(parent) = resolver.get(&parent_entry) else {
            // Parent not present → orphan rooted at the missing parent entry.
            return orphan_path(parent_entry, &components);
        };

        // Stale-parent (slot reused since this child recorded it, §A.4): the
        // resolved parent's current sequence differs from the expected one.
        if parent.sequence != current.parent_seq {
            return orphan_path(parent_entry, &components);
        }

        components.push(parent.name.as_str());
        visited.push(parent_entry);
        current = parent;
    }

    components.reverse();
    ResolvedPath {
        path: components.join(&SEP.to_string()),
        diagnostic: None,
    }
}

fn orphan_path(parent_entry: u64, components: &[&str]) -> ResolvedPath {
    let mut parts: Vec<&str> = components.to_vec();
    parts.reverse();
    let tail = parts.join(&SEP.to_string());
    ResolvedPath {
        path: format!("{SEP}$Orphan{SEP}{parent_entry}{SEP}{tail}"),
        diagnostic: Some("orphan-parent"),
    }
}

fn cycle_path(components: &[&str]) -> ResolvedPath {
    let mut parts: Vec<&str> = components.to_vec();
    parts.reverse();
    let tail = parts.join(&SEP.to_string());
    ResolvedPath {
        path: format!("{SEP}$Cycle{SEP}{tail}"),
        diagnostic: Some("cycle"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, parent: u64, seq: u16, parent_seq: u16, is_dir: bool) -> ResolverNode {
        ResolverNode {
            name: name.into(),
            parent_entry: parent,
            parent_seq,
            is_dir,
            sequence: seq,
        }
    }

    fn index() -> BTreeMap<u64, ResolverNode> {
        let mut m = BTreeMap::new();
        // 5 = root; 10 = Windows; 20 = System32; 30 = cmd.exe
        m.insert(5, node(".", 5, 5, 5, true));
        m.insert(10, node("Windows", 5, 1, 5, true));
        m.insert(20, node("System32", 10, 1, 1, true));
        m.insert(30, node("cmd.exe", 20, 1, 1, false));
        m
    }

    #[test]
    fn reconstructs_nested_path() {
        let m = index();
        let r = resolve(&m, 30, 256);
        assert_eq!(r.path, "Windows\\System32\\cmd.exe");
        assert_eq!(r.diagnostic, None);
    }

    #[test]
    fn root_level_file() {
        let mut m = index();
        m.insert(40, node("pagefile.sys", 5, 1, 5, false));
        let r = resolve(&m, 40, 256);
        assert_eq!(r.path, "pagefile.sys");
    }

    #[test]
    fn missing_parent_is_orphan() {
        let mut m = BTreeMap::new();
        m.insert(30, node("evil.exe", 999, 1, 7, false));
        let r = resolve(&m, 30, 256);
        assert!(r.path.starts_with("\\$Orphan\\999\\"));
        assert_eq!(r.diagnostic, Some("orphan-parent"));
    }

    #[test]
    fn stale_parent_is_orphan() {
        // Child recorded parent_seq=7 but the parent slot now has sequence=9.
        let mut m = BTreeMap::new();
        m.insert(10, node("ReusedDir", 5, 9, 5, true));
        m.insert(30, node("ghost.txt", 10, 1, 7, false));
        let r = resolve(&m, 30, 256);
        assert_eq!(r.diagnostic, Some("orphan-parent"));
    }

    #[test]
    fn cycle_is_bounded() {
        // 100 -> 200 -> 100 loop.
        let mut m = BTreeMap::new();
        m.insert(100, node("a", 200, 1, 1, true));
        m.insert(200, node("b", 100, 1, 1, true));
        let r = resolve(&m, 100, 256);
        assert_eq!(r.diagnostic, Some("cycle"));
        assert!(r.path.starts_with("\\$Cycle\\"));
    }

    #[test]
    fn absurd_depth_is_bounded() {
        let mut m = BTreeMap::new();
        // A long non-looping chain deeper than max_depth=4.
        for i in 10..40u64 {
            m.insert(i, node(&format!("d{i}"), i + 1, 1, 1, true));
        }
        m.insert(40, node("top", 5, 1, 5, true));
        let r = resolve(&m, 10, 4);
        assert_eq!(r.diagnostic, Some("cycle"));
    }
}
