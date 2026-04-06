use std::num::NonZeroUsize;

use lru::LruCache;

/// Cached result of a bash command execution.
#[derive(Clone, Debug)]
pub struct CachedResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[allow(dead_code)]
pub struct CommandCacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

/// In-memory LRU cache for command output. Safe because the VFS is read-only.
pub struct CommandCache {
    cache: LruCache<String, CachedResult>,
    max_output_bytes: usize,
    hits: u64,
    misses: u64,
}

impl CommandCache {
    pub fn new(max_entries: usize, max_output_bytes: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::new(1000).unwrap())),
            max_output_bytes,
            hits: 0,
            misses: 0,
        }
    }

    fn key(cwd: &str, command: &str) -> String {
        format!("{}\0{}", cwd, command)
    }

    pub fn get(&mut self, cwd: &str, command: &str) -> Option<CachedResult> {
        let key = Self::key(cwd, command);
        if let Some(entry) = self.cache.get(&key) {
            self.hits += 1;
            Some(entry.clone())
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn set(&mut self, cwd: &str, command: &str, result: CachedResult) {
        let output_bytes = result.stdout.len() + result.stderr.len();
        if output_bytes > self.max_output_bytes {
            return;
        }
        let key = Self::key(cwd, command);
        self.cache.put(key, result);
    }

    #[allow(dead_code)]
    pub fn stats(&self) -> CommandCacheStats {
        let total = self.hits + self.misses;
        CommandCacheStats {
            entries: self.cache.len(),
            hits: self.hits,
            misses: self.misses,
            hit_rate: if total > 0 {
                self.hits as f64 / total as f64
            } else {
                0.0
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(stdout: &str, exit_code: i32) -> CachedResult {
        CachedResult {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code,
        }
    }

    #[test]
    fn returns_none_on_cache_miss() {
        let mut cache = CommandCache::new(10, 1024);
        assert!(cache.get("/home", "echo hello").is_none());
    }

    #[test]
    fn returns_cached_result_on_hit() {
        let mut cache = CommandCache::new(10, 1024);
        cache.set("/home", "echo hello", result("hello\n", 0));
        let hit = cache.get("/home", "echo hello").unwrap();
        assert_eq!(hit.stdout, "hello\n");
        assert_eq!(hit.exit_code, 0);
    }

    #[test]
    fn differentiates_by_cwd() {
        let mut cache = CommandCache::new(10, 1024);
        cache.set("/a", "ls", result("a-files", 0));
        cache.set("/b", "ls", result("b-files", 0));

        assert_eq!(cache.get("/a", "ls").unwrap().stdout, "a-files");
        assert_eq!(cache.get("/b", "ls").unwrap().stdout, "b-files");
    }

    #[test]
    fn tracks_hit_miss_stats() {
        let mut cache = CommandCache::new(10, 1024);
        cache.set("/home", "echo 1", result("1", 0));

        // 1 miss
        cache.get("/home", "echo 2");
        // 2 hits
        cache.get("/home", "echo 1");
        cache.get("/home", "echo 1");

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn evicts_oldest_entry_when_at_capacity() {
        let mut cache = CommandCache::new(2, 1024);
        cache.set("/home", "cmd1", result("r1", 0));
        cache.set("/home", "cmd2", result("r2", 0));
        // This should evict cmd1 (oldest / least-recently-used)
        cache.set("/home", "cmd3", result("r3", 0));

        assert!(cache.get("/home", "cmd1").is_none(), "cmd1 should have been evicted");
        assert!(cache.get("/home", "cmd2").is_some());
        assert!(cache.get("/home", "cmd3").is_some());
        assert_eq!(cache.stats().entries, 2);
    }

    #[test]
    fn promotes_entry_on_access() {
        let mut cache = CommandCache::new(2, 1024);
        cache.set("/home", "cmd1", result("r1", 0));
        cache.set("/home", "cmd2", result("r2", 0));

        // Access cmd1 so it becomes most-recently-used
        cache.get("/home", "cmd1");

        // Insert cmd3 — should evict cmd2 (now the LRU), not cmd1
        cache.set("/home", "cmd3", result("r3", 0));

        assert!(cache.get("/home", "cmd1").is_some(), "cmd1 should still be present (was promoted)");
        assert!(cache.get("/home", "cmd2").is_none(), "cmd2 should have been evicted");
        assert!(cache.get("/home", "cmd3").is_some());
    }

    #[test]
    fn skips_caching_output_exceeding_max_output_bytes() {
        let mut cache = CommandCache::new(10, 16);
        // stdout + stderr = 20 bytes > 16
        cache.set("/home", "big", CachedResult {
            stdout: "a]".repeat(10),
            stderr: String::new(),
            exit_code: 0,
        });
        assert!(cache.get("/home", "big").is_none(), "oversized output should not be cached");
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn does_not_evict_when_updating_existing_entry() {
        let mut cache = CommandCache::new(2, 1024);
        cache.set("/home", "cmd1", result("old", 0));
        cache.set("/home", "cmd2", result("r2", 0));

        // Update cmd1 — should NOT evict cmd2 since key already exists
        cache.set("/home", "cmd1", result("new", 0));

        assert_eq!(cache.get("/home", "cmd1").unwrap().stdout, "new");
        assert!(cache.get("/home", "cmd2").is_some(), "cmd2 should not have been evicted");
        assert_eq!(cache.stats().entries, 2);
    }
}
