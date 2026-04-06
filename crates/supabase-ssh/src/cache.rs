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
