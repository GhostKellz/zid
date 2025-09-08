//! Environment-based configuration loading for ZID
//! Supports loading from .env files and environment variables for easy SSO setup

const std = @import("std");
const root = @import("../root.zig");

/// Environment configuration loader
pub const EnvConfig = struct {
    allocator: std.mem.Allocator,
    env_map: std.StringHashMap([]const u8),
    
    pub fn init(allocator: std.mem.Allocator) EnvConfig {
        return EnvConfig{
            .allocator = allocator,
            .env_map = std.StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *EnvConfig) void {
        var iterator = self.env_map.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.env_map.deinit();
    }
    
    /// Load configuration from .env file
    pub fn loadFromFile(self: *EnvConfig, file_path: []const u8) !void {
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.info("No .env file found at: {s}", .{file_path});
                return;
            },
            else => return err,
        };
        defer file.close();
        
        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024); // 1MB max
        defer self.allocator.free(content);
        
        try self.parseEnvContent(content);
    }
    
    /// Load configuration from environment variables
    pub fn loadFromEnvironment(self: *EnvConfig) !void {
        // Load system environment variables that start with ZID_
        var env_map = try std.process.getEnvMap(self.allocator);
        defer env_map.deinit();
        
        var iterator = env_map.iterator();
        while (iterator.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, "ZID_")) {
                const key = try self.allocator.dupe(u8, entry.key_ptr.*);
                const value = try self.allocator.dupe(u8, entry.value_ptr.*);
                try self.env_map.put(key, value);
            }
        }
    }
    
    /// Parse .env file content
    pub fn parseEnvContent(self: *EnvConfig, content: []const u8) !void {
        var lines = std.mem.splitSequence(u8, content, "\n");
        
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");
            
            // Skip empty lines and comments
            if (trimmed.len == 0 or trimmed[0] == '#') continue;
            
            // Find the = separator
            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
                var value = std.mem.trim(u8, trimmed[eq_pos + 1..], " \t");
                
                // Handle quoted values
                if (value.len >= 2 and 
                    ((value[0] == '"' and value[value.len - 1] == '"') or
                     (value[0] == '\'' and value[value.len - 1] == '\''))) {
                    value = value[1..value.len - 1];
                }
                
                const key_copy = try self.allocator.dupe(u8, key);
                const value_copy = try self.allocator.dupe(u8, value);
                try self.env_map.put(key_copy, value_copy);
            }
        }
    }
    
    /// Get a configuration value
    pub fn get(self: *const EnvConfig, key: []const u8) ?[]const u8 {
        return self.env_map.get(key);
    }
    
    /// Get a configuration value with default
    pub fn getWithDefault(self: *const EnvConfig, key: []const u8, default: []const u8) []const u8 {
        return self.get(key) orelse default;
    }
    
    /// Get required configuration value (returns error if missing)
    pub fn getRequired(self: *const EnvConfig, key: []const u8) ![]const u8 {
        return self.get(key) orelse {
            std.log.err("Required configuration key missing: {s}", .{key});
            return error.MissingRequiredConfig;
        };
    }
    
    /// Convert to ZID Config
    pub fn toZidConfig(self: *const EnvConfig) !root.Config {
        return root.Config{
            .client_id = try self.getRequired("ZID_CLIENT_ID"),
            .client_secret = self.get("ZID_CLIENT_SECRET"),
            .redirect_uri = try self.getRequired("ZID_REDIRECT_URI"),
            .scopes = try self.parseScopes(),
            .issuer_url = try self.getRequired("ZID_ISSUER_URL"),
            .audience = self.get("ZID_AUDIENCE"),
            
            // Security settings
            .enforce_https = std.mem.eql(u8, self.getWithDefault("ZID_ENFORCE_HTTPS", "true"), "true"),
            .allow_insecure_http = std.mem.eql(u8, self.getWithDefault("ZID_ALLOW_INSECURE_HTTP", "false"), "true"),
            .clock_skew_seconds = std.fmt.parseInt(u32, self.getWithDefault("ZID_CLOCK_SKEW_SECONDS", "300"), 10) catch 300,
            
            // PKCE settings
            .force_pkce = std.mem.eql(u8, self.getWithDefault("ZID_FORCE_PKCE", "true"), "true"),
            .pkce_method = if (std.mem.eql(u8, self.getWithDefault("ZID_PKCE_METHOD", "S256"), "plain")) 
                root.PkceMethod.plain else root.PkceMethod.S256,
            
            // Session settings
            .session_timeout_seconds = std.fmt.parseInt(u32, self.getWithDefault("ZID_SESSION_TIMEOUT", "3600"), 10) catch 3600,
            .refresh_token_rotation = std.mem.eql(u8, self.getWithDefault("ZID_REFRESH_TOKEN_ROTATION", "true"), "true"),
        };
    }
    
    /// Parse scopes from environment
    fn parseScopes(self: *const EnvConfig) ![]const []const u8 {
        const scopes_str = self.getWithDefault("ZID_SCOPES", "openid profile email");
        var scopes_list = std.ArrayList([]const u8){};
        defer scopes_list.deinit(self.allocator);
        
        var scopes_it = std.mem.splitSequence(u8, scopes_str, " ");
        while (scopes_it.next()) |scope| {
            const trimmed = std.mem.trim(u8, scope, " \t");
            if (trimmed.len > 0) {
                const scope_copy = try self.allocator.dupe(u8, trimmed);
                try scopes_list.append(self.allocator, scope_copy);
            }
        }
        
        return scopes_list.toOwnedSlice(self.allocator);
    }
};

/// Quick load from .env file and environment
pub fn loadConfig(allocator: std.mem.Allocator, env_file_path: ?[]const u8) !root.Config {
    var env_config = EnvConfig.init(allocator);
    defer env_config.deinit();
    
    // Load from .env file if specified
    if (env_file_path) |path| {
        try env_config.loadFromFile(path);
    }
    
    // Load from environment variables (takes precedence)
    try env_config.loadFromEnvironment();
    
    return try env_config.toZidConfig();
}

/// Load from default .env location
pub fn loadFromDefaultEnv(allocator: std.mem.Allocator) !root.Config {
    return loadConfig(allocator, ".env");
}

test "env config parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var env_config = EnvConfig.init(allocator);
    defer env_config.deinit();
    
    const test_content = 
        \\# ZID Configuration
        \\ZID_CLIENT_ID=test_client_id
        \\ZID_CLIENT_SECRET="test_client_secret"
        \\ZID_REDIRECT_URI=https://example.com/callback
        \\ZID_ISSUER_URL=https://auth.example.com
        \\ZID_SCOPES="openid profile email"
        \\ZID_ENFORCE_HTTPS=true
    ;
    
    try env_config.parseEnvContent(test_content);
    
    try testing.expectEqualStrings("test_client_id", env_config.get("ZID_CLIENT_ID").?);
    try testing.expectEqualStrings("test_client_secret", env_config.get("ZID_CLIENT_SECRET").?);
    try testing.expectEqualStrings("https://example.com/callback", env_config.get("ZID_REDIRECT_URI").?);
}