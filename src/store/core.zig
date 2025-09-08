//! Storage and caching layer for OIDC/OAuth2/SAML
//! Provides in-memory cache with optional persistent storage for tokens, JWKS, etc.

const std = @import("std");
const time = @import("../time/core.zig");
const jose = @import("../jose/core.zig");

/// Cache entry with TTL
pub const CacheEntry = struct {
    value: []const u8,
    expires_at: time.Timestamp,
    
    pub fn isExpired(self: *const CacheEntry) bool {
        return time.now() >= self.expires_at;
    }
    
    pub fn init(allocator: std.mem.Allocator, value: []const u8, ttl_seconds: u32) !CacheEntry {
        return CacheEntry{
            .value = try allocator.dupe(u8, value),
            .expires_at = time.now() + @as(i64, @intCast(ttl_seconds)),
        };
    }
    
    pub fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

/// In-memory cache with TTL support
pub const MemoryCache = struct {
    entries: std.StringHashMapUnmanaged(CacheEntry),
    allocator: std.mem.Allocator,
    default_ttl_seconds: u32,
    max_size: usize,
    
    pub fn init(allocator: std.mem.Allocator, options: CacheOptions) MemoryCache {
        return MemoryCache{
            .entries = .empty,
            .allocator = allocator,
            .default_ttl_seconds = options.default_ttl_seconds,
            .max_size = options.max_size,
        };
    }
    
    pub const CacheOptions = struct {
        default_ttl_seconds: u32 = 300, // 5 minutes
        max_size: usize = 1000,
    };
    
    pub fn deinit(self: *MemoryCache) void {
        self.clear();
        self.entries.deinit(self.allocator);
    }
    
    /// Store value in cache
    pub fn put(self: *MemoryCache, key: []const u8, value: []const u8, ttl_seconds: ?u32) !void {
        // Remove existing entry if present
        if (self.entries.getPtr(key)) |existing| {
            existing.deinit(self.allocator);
            _ = self.entries.remove(key);
            self.allocator.free(key);
        }
        
        // Check size limit
        if (self.entries.count() >= self.max_size) {
            try self.evict();
        }
        
        const owned_key = try self.allocator.dupe(u8, key);
        const ttl = ttl_seconds orelse self.default_ttl_seconds;
        const entry = try CacheEntry.init(self.allocator, value, ttl);
        
        try self.entries.put(self.allocator, owned_key, entry);
    }
    
    /// Get value from cache (returns null if not found or expired)
    pub fn get(self: *MemoryCache, key: []const u8) ?[]const u8 {
        if (self.entries.getPtr(key)) |entry| {
            if (entry.isExpired()) {
                // Remove expired entry
                entry.deinit(self.allocator);
                _ = self.entries.remove(key);
                return null;
            }
            return entry.value;
        }
        return null;
    }
    
    /// Remove entry from cache
    pub fn remove(self: *MemoryCache, key: []const u8) void {
        if (self.entries.getPtr(key)) |entry| {
            entry.deinit(self.allocator);
            _ = self.entries.remove(key);
        }
    }
    
    /// Clear all entries
    pub fn clear(self: *MemoryCache) void {
        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.clearRetainingCapacity();
    }
    
    /// Evict expired entries
    pub fn evictExpired(self: *MemoryCache) void {
        var to_remove = std.ArrayList([]const u8){};
        defer {
            for (to_remove.items) |key| {
                self.allocator.free(key);
            }
            to_remove.deinit(self.allocator);
        }
        
        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                if (self.allocator.dupe(u8, entry.key_ptr.*)) |key_copy| {
                    to_remove.append(self.allocator, key_copy) catch continue;
                } else |_| continue;
            }
        }
        
        for (to_remove.items) |key| {
            self.remove(key);
        }
    }
    
    /// Evict oldest entries to make room
    fn evict(self: *MemoryCache) !void {
        // Simple eviction: remove expired entries first, then oldest
        self.evictExpired();
        
        // If still at capacity, remove some entries (simplified LRU)
        if (self.entries.count() >= self.max_size) {
            var to_remove = std.ArrayList([]const u8){};
            defer {
                for (to_remove.items) |key| {
                    self.allocator.free(key);
                }
                to_remove.deinit(self.allocator);
            }
            
            var iterator = self.entries.iterator();
            var count: usize = 0;
            const max_to_remove = self.entries.count() / 4; // Remove 25%
            
            while (iterator.next()) |entry| {
                if (count >= max_to_remove) break;
                try to_remove.append(self.allocator, try self.allocator.dupe(u8, entry.key_ptr.*));
                count += 1;
            }
            
            for (to_remove.items) |key| {
                self.remove(key);
            }
        }
    }
    
    /// Get cache statistics
    pub fn getStats(self: *const MemoryCache) CacheStats {
        var expired_count: usize = 0;
        var iterator = self.entries.iterator();
        
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                expired_count += 1;
            }
        }
        
        return CacheStats{
            .total_entries = self.entries.count(),
            .expired_entries = expired_count,
            .active_entries = self.entries.count() - expired_count,
        };
    }
    
    pub const CacheStats = struct {
        total_entries: usize,
        expired_entries: usize,
        active_entries: usize,
    };
};

/// JWKS (JSON Web Key Set) cache with key ID lookup
pub const JwksCache = struct {
    cache: MemoryCache,
    jwks_url: ?[]const u8,
    keys: std.StringHashMapUnmanaged(jose.JsonWebKey),
    last_updated: time.Timestamp,
    update_interval_seconds: u32,
    
    pub fn init(allocator: std.mem.Allocator, options: JwksCacheOptions) JwksCache {
        return JwksCache{
            .cache = MemoryCache.init(allocator, .{
                .default_ttl_seconds = options.cache_ttl_seconds,
                .max_size = options.max_keys,
            }),
            .jwks_url = if (options.jwks_url) |url| 
                allocator.dupe(u8, url) catch null else null,
            .keys = .empty,
            .last_updated = 0,
            .update_interval_seconds = options.update_interval_seconds,
        };
    }
    
    pub const JwksCacheOptions = struct {
        jwks_url: ?[]const u8 = null,
        cache_ttl_seconds: u32 = 3600, // 1 hour
        max_keys: usize = 100,
        update_interval_seconds: u32 = 300, // 5 minutes
    };
    
    pub fn deinit(self: *JwksCache) void {
        self.cache.deinit();
        
        if (self.jwks_url) |url| {
            self.cache.allocator.free(url);
        }
        
        var iterator = self.keys.iterator();
        while (iterator.next()) |entry| {
            self.cache.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.keys.deinit(self.cache.allocator);
    }
    
    /// Get key by key ID
    pub fn getKey(self: *JwksCache, kid: []const u8) ?*const jose.JsonWebKey {
        // Check if we need to update the cache
        if (self.shouldUpdate()) {
            self.updateKeys() catch {}; // Ignore errors, use cached keys
        }
        
        return self.keys.getPtr(kid);
    }
    
    /// Add key to cache
    pub fn addKey(self: *JwksCache, key: jose.JsonWebKey) !void {
        if (key.kid == null) return error.MissingKeyId;
        
        const kid = key.kid.?;
        const owned_kid = try self.cache.allocator.dupe(u8, kid);
        
        // Remove existing key if present
        if (self.keys.getPtr(owned_kid)) |existing| {
            existing.deinit();
        }
        
        try self.keys.put(self.cache.allocator, owned_kid, key);
    }
    
    /// Check if cache should be updated
    fn shouldUpdate(self: *const JwksCache) bool {
        const now = time.now();
        return (now - self.last_updated) >= self.update_interval_seconds;
    }
    
    /// Update keys from JWKS URL (placeholder implementation)
    fn updateKeys(self: *JwksCache) !void {
        // In a real implementation, this would:
        // 1. Fetch JWKS from self.jwks_url using HTTP client
        // 2. Parse the JSON response
        // 3. Extract JWK entries
        // 4. Update the cache
        
        self.last_updated = time.now();
    }
};

/// Token storage for OAuth2/OIDC tokens
pub const TokenStore = struct {
    cache: MemoryCache,
    
    pub fn init(allocator: std.mem.Allocator) TokenStore {
        return TokenStore{
            .cache = MemoryCache.init(allocator, .{
                .default_ttl_seconds = 3600, // 1 hour default
                .max_size = 10000,
            }),
        };
    }
    
    pub fn deinit(self: *TokenStore) void {
        self.cache.deinit();
    }
    
    /// Store access token
    pub fn storeAccessToken(self: *TokenStore, client_id: []const u8, access_token: []const u8, expires_in: u32) !void {
        const key = try std.fmt.allocPrint(
            self.cache.allocator,
            "access_token:{s}",
            .{client_id}
        );
        defer self.cache.allocator.free(key);
        
        try self.cache.put(key, access_token, expires_in);
    }
    
    /// Get access token
    pub fn getAccessToken(self: *TokenStore, client_id: []const u8) ?[]const u8 {
        const key = std.fmt.allocPrint(
            self.cache.allocator,
            "access_token:{s}",
            .{client_id}
        ) catch return null;
        defer self.cache.allocator.free(key);
        
        return self.cache.get(key);
    }
    
    /// Store refresh token
    pub fn storeRefreshToken(self: *TokenStore, client_id: []const u8, refresh_token: []const u8) !void {
        const key = try std.fmt.allocPrint(
            self.cache.allocator,
            "refresh_token:{s}",
            .{client_id}
        );
        defer self.cache.allocator.free(key);
        
        // Refresh tokens typically have longer TTL
        try self.cache.put(key, refresh_token, 86400 * 30); // 30 days
    }
    
    /// Get refresh token
    pub fn getRefreshToken(self: *TokenStore, client_id: []const u8) ?[]const u8 {
        const key = std.fmt.allocPrint(
            self.cache.allocator,
            "refresh_token:{s}",
            .{client_id}
        ) catch return null;
        defer self.cache.allocator.free(key);
        
        return self.cache.get(key);
    }
    
    /// Remove tokens for client
    pub fn removeTokens(self: *TokenStore, client_id: []const u8) void {
        const access_key = std.fmt.allocPrint(
            self.cache.allocator,
            "access_token:{s}",
            .{client_id}
        ) catch return;
        defer self.cache.allocator.free(access_key);
        
        const refresh_key = std.fmt.allocPrint(
            self.cache.allocator,
            "refresh_token:{s}",
            .{client_id}
        ) catch return;
        defer self.cache.allocator.free(refresh_key);
        
        self.cache.remove(access_key);
        self.cache.remove(refresh_key);
    }
};

/// Session storage for user sessions
pub const SessionStore = struct {
    cache: MemoryCache,
    
    pub fn init(allocator: std.mem.Allocator) SessionStore {
        return SessionStore{
            .cache = MemoryCache.init(allocator, .{
                .default_ttl_seconds = 3600, // 1 hour sessions
                .max_size = 50000,
            }),
        };
    }
    
    pub fn deinit(self: *SessionStore) void {
        self.cache.deinit();
    }
    
    /// Create session
    pub fn createSession(self: *SessionStore, session_id: []const u8, user_data: []const u8, ttl_seconds: u32) !void {
        try self.cache.put(session_id, user_data, ttl_seconds);
    }
    
    /// Get session data
    pub fn getSession(self: *SessionStore, session_id: []const u8) ?[]const u8 {
        return self.cache.get(session_id);
    }
    
    /// Update session TTL
    pub fn refreshSession(self: *SessionStore, session_id: []const u8, ttl_seconds: u32) !void {
        if (self.cache.get(session_id)) |data| {
            const owned_data = try self.cache.allocator.dupe(u8, data);
            defer self.cache.allocator.free(owned_data);
            try self.cache.put(session_id, owned_data, ttl_seconds);
        }
    }
    
    /// Remove session
    pub fn removeSession(self: *SessionStore, session_id: []const u8) void {
        self.cache.remove(session_id);
    }
};

/// Nonce store for replay attack prevention
pub const NonceStore = struct {
    cache: MemoryCache,
    
    pub fn init(allocator: std.mem.Allocator) NonceStore {
        return NonceStore{
            .cache = MemoryCache.init(allocator, .{
                .default_ttl_seconds = 600, // 10 minutes for nonces
                .max_size = 100000,
            }),
        };
    }
    
    pub fn deinit(self: *NonceStore) void {
        self.cache.deinit();
    }
    
    /// Check if nonce has been used (and mark it as used)
    pub fn checkAndMarkNonce(self: *NonceStore, nonce: []const u8) !bool {
        if (self.cache.get(nonce) != null) {
            return false; // Already used
        }
        
        try self.cache.put(nonce, "used", null); // Use default TTL
        return true; // First use
    }
    
    /// Check if JTI (JWT ID) has been used
    pub fn checkAndMarkJti(self: *NonceStore, jti: []const u8) !bool {
        const key = try std.fmt.allocPrint(
            self.cache.allocator,
            "jti:{s}",
            .{jti}
        );
        defer self.cache.allocator.free(key);
        
        if (self.cache.get(key) != null) {
            return false; // Already used
        }
        
        try self.cache.put(key, "used", null);
        return true; // First use
    }
};

test "memory cache basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var cache = MemoryCache.init(allocator, .{ 
        .default_ttl_seconds = 10,
        .max_size = 100,
    });
    defer cache.deinit();
    
    // Test put and get
    try cache.put("key1", "value1", null);
    const value = cache.get("key1");
    try testing.expect(value != null);
    try testing.expectEqualStrings("value1", value.?);
    
    // Test nonexistent key
    try testing.expect(cache.get("nonexistent") == null);
    
    // Test remove
    cache.remove("key1");
    try testing.expect(cache.get("key1") == null);
    
    // Test stats
    try cache.put("key2", "value2", null);
    try cache.put("key3", "value3", null);
    const stats = cache.getStats();
    try testing.expect(stats.total_entries == 2);
}

test "token store operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var store = TokenStore.init(allocator);
    defer store.deinit();
    
    // Test access token storage
    try store.storeAccessToken("client123", "access_token_123", 3600);
    const token = store.getAccessToken("client123");
    try testing.expect(token != null);
    try testing.expectEqualStrings("access_token_123", token.?);
    
    // Test refresh token storage
    try store.storeRefreshToken("client123", "refresh_token_123");
    const refresh = store.getRefreshToken("client123");
    try testing.expect(refresh != null);
    try testing.expectEqualStrings("refresh_token_123", refresh.?);
    
    // Test token removal
    store.removeTokens("client123");
    try testing.expect(store.getAccessToken("client123") == null);
    try testing.expect(store.getRefreshToken("client123") == null);
}

test "nonce store replay protection" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var store = NonceStore.init(allocator);
    defer store.deinit();
    
    // First use should succeed
    const first_use = try store.checkAndMarkNonce("nonce123");
    try testing.expect(first_use);
    
    // Second use should fail (replay)
    const second_use = try store.checkAndMarkNonce("nonce123");
    try testing.expect(!second_use);
    
    // Different nonce should succeed
    const different_nonce = try store.checkAndMarkNonce("nonce456");
    try testing.expect(different_nonce);
}