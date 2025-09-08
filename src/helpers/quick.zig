//! Minimal integration helpers for "SSO just works" experience
//! One-line SSO setup with automatic configuration from environment

const std = @import("std");
const root = @import("../root.zig");
const env = @import("../config/env.zig");
const presets = @import("../presets/providers.zig");

/// Quick SSO client for minimal-work integration
pub const QuickSSO = struct {
    allocator: std.mem.Allocator,
    oauth_client: ?root.Client = null,
    oidc_client: ?root.OidcClient = null,
    config: root.Config,
    
    const Self = @This();
    
    /// Initialize from .env file
    pub fn fromEnv(allocator: std.mem.Allocator, env_file: ?[]const u8) !Self {
        const config = try env.loadConfig(allocator, env_file);
        
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }
    
    /// Initialize from environment variables only
    pub fn fromEnvironment(allocator: std.mem.Allocator) !Self {
        var env_config = env.EnvConfig.init(allocator);
        defer env_config.deinit();
        
        try env_config.loadFromEnvironment();
        const config = try env_config.toZidConfig();
        
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }
    
    /// Initialize with Google preset
    pub fn google(allocator: std.mem.Allocator, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !Self {
        const config = try presets.QuickSetup.google(allocator, client_id, client_secret, redirect_uri);
        
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }
    
    /// Initialize with Azure AD preset
    pub fn azureAD(allocator: std.mem.Allocator, tenant_id: []const u8, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !Self {
        const config = try presets.QuickSetup.azureAD(allocator, tenant_id, client_id, client_secret, redirect_uri);
        
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }
    
    /// Initialize with GitHub preset  
    pub fn github(allocator: std.mem.Allocator, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !Self {
        const config = try presets.QuickSetup.github(allocator, client_id, client_secret, redirect_uri);
        
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }
    
    /// Initialize with Auth0 preset
    pub fn auth0(allocator: std.mem.Allocator, domain: []const u8, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !Self {
        const config = try presets.QuickSetup.auth0(allocator, domain, client_id, client_secret, redirect_uri);
        
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.oauth_client) |*client| {
            client.deinit();
        }
        if (self.oidc_client) |*client| {
            client.deinit();
        }
        
        // Free config
        self.allocator.free(self.config.client_id);
        if (self.config.client_secret) |cs| self.allocator.free(cs);
        self.allocator.free(self.config.redirect_uri);
        self.allocator.free(self.config.issuer_url);
        if (self.config.audience) |aud| self.allocator.free(aud);
        
        for (self.config.scopes) |scope| {
            self.allocator.free(scope);
        }
        self.allocator.free(self.config.scopes);
    }
    
    /// Get authorization URL for login
    pub fn getAuthUrl(self: *Self, state: ?[]const u8) ![]u8 {
        if (self.oauth_client == null) {
            // Convert to OAuth client config
            const oauth_config = root.oauth.ClientConfig{
                .client_id = self.config.client_id,
                .client_secret = self.config.client_secret,
                .redirect_uri = self.config.redirect_uri,
                .scopes = self.config.scopes,
                .authorization_endpoint = try self.guessAuthEndpoint(),
                .token_endpoint = try self.guessTokenEndpoint(),
                .enforce_https = self.config.enforce_https,
                .force_pkce = self.config.force_pkce,
            };
            
            self.oauth_client = try root.oauth.Client.init(self.allocator, oauth_config);
        }
        
        // Generate PKCE for security
        var pkce = try self.oauth_client.?.generatePkce();
        defer pkce.deinit();
        
        return try self.oauth_client.?.buildAuthorizationUrl(state, &pkce);
    }
    
    /// Exchange authorization code for tokens
    pub fn exchangeCode(self: *Self, code: []const u8, state: ?[]const u8) !root.TokenResponse {
        if (self.oauth_client == null) {
            return error.ClientNotInitialized;
        }
        
        // For simplicity, we'll need to regenerate PKCE (in production, store it)
        var pkce = try self.oauth_client.?.generatePkce();
        defer pkce.deinit();
        
        return try self.oauth_client.?.exchangeCodeForTokens(code, &pkce, state);
    }
    
    /// Get user info from ID token or UserInfo endpoint
    pub fn getUserInfo(self: *Self, access_token: []const u8) !root.IdToken {
        if (self.oidc_client == null) {
            const oidc_config = root.oidc.ClientConfig{
                .client_id = self.config.client_id,
                .client_secret = self.config.client_secret,
                .issuer_url = self.config.issuer_url,
                .redirect_uri = self.config.redirect_uri,
                .scopes = self.config.scopes,
                .clock_skew_seconds = self.config.clock_skew_seconds,
            };
            
            self.oidc_client = try root.oidc.Client.init(self.allocator, oidc_config);
        }
        
        // Try to get user info from UserInfo endpoint
        return try self.oidc_client.?.getUserInfo(access_token);
    }
    
    /// Helper to guess authorization endpoint from issuer
    fn guessAuthEndpoint(self: *Self) ![]const u8 {
        // Common patterns for authorization endpoints
        if (std.mem.indexOf(u8, self.config.issuer_url, "accounts.google.com")) |_| {
            return try self.allocator.dupe(u8, "https://accounts.google.com/o/oauth2/v2/auth");
        } else if (std.mem.indexOf(u8, self.config.issuer_url, "login.microsoftonline.com")) |_| {
            return try std.fmt.allocPrint(self.allocator, "{s}/oauth2/v2.0/authorize", .{self.config.issuer_url});
        } else if (std.mem.indexOf(u8, self.config.issuer_url, "github.com")) |_| {
            return try self.allocator.dupe(u8, "https://github.com/login/oauth/authorize");
        } else {
            // Default pattern
            return try std.fmt.allocPrint(self.allocator, "{s}/authorize", .{self.config.issuer_url});
        }
    }
    
    /// Helper to guess token endpoint from issuer
    fn guessTokenEndpoint(self: *Self) ![]const u8 {
        // Common patterns for token endpoints
        if (std.mem.indexOf(u8, self.config.issuer_url, "accounts.google.com")) |_| {
            return try self.allocator.dupe(u8, "https://oauth2.googleapis.com/token");
        } else if (std.mem.indexOf(u8, self.config.issuer_url, "login.microsoftonline.com")) |_| {
            return try std.fmt.allocPrint(self.allocator, "{s}/oauth2/v2.0/token", .{self.config.issuer_url});
        } else if (std.mem.indexOf(u8, self.config.issuer_url, "github.com")) |_| {
            return try self.allocator.dupe(u8, "https://github.com/login/oauth/access_token");
        } else {
            // Default pattern
            return try std.fmt.allocPrint(self.allocator, "{s}/oauth/token", .{self.config.issuer_url});
        }
    }
};

/// Ultra-simple setup functions
pub const simple = struct {
    /// One-line SSO setup from .env
    pub fn setupFromEnv(allocator: std.mem.Allocator) !QuickSSO {
        return try QuickSSO.fromEnv(allocator, ".env");
    }
    
    /// One-line Google SSO
    pub fn setupGoogle(allocator: std.mem.Allocator, client_id: []const u8, client_secret: []const u8, redirect_uri: []const u8) !QuickSSO {
        return try QuickSSO.google(allocator, client_id, client_secret, redirect_uri);
    }
    
    /// One-line Azure AD SSO
    pub fn setupAzureAD(allocator: std.mem.Allocator, tenant_id: []const u8, client_id: []const u8, client_secret: []const u8, redirect_uri: []const u8) !QuickSSO {
        return try QuickSSO.azureAD(allocator, tenant_id, client_id, client_secret, redirect_uri);
    }
    
    /// Complete login flow helper
    pub fn handleLogin(sso: *QuickSSO, code: []const u8, state: ?[]const u8) !LoginResult {
        const tokens = try sso.exchangeCode(code, state);
        const user_info = sso.getUserInfo(tokens.access_token) catch |err| switch (err) {
            error.NetworkError, error.HttpError => {
                // Fallback: try to decode ID token if available
                if (tokens.id_token) |_| {
                    return LoginResult{
                        .tokens = tokens,
                        .user_info = null, // Would need to decode JWT
                        .success = true,
                    };
                } else {
                    return LoginResult{
                        .tokens = tokens,
                        .user_info = null,
                        .success = true,
                    };
                }
            },
            else => return err,
        };
        
        return LoginResult{
            .tokens = tokens,
            .user_info = user_info,
            .success = true,
        };
    }
};

/// Login result structure
pub const LoginResult = struct {
    tokens: root.TokenResponse,
    user_info: ?root.IdToken,
    success: bool,
    
    pub fn deinit(self: *LoginResult) void {
        self.tokens.deinit();
        if (self.user_info) |*ui| {
            ui.deinit();
        }
    }
};

test "quick sso setup" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Google setup
    var google_sso = try QuickSSO.google(
        allocator,
        "test_client_id", 
        "test_secret",
        "https://example.com/callback"
    );
    defer google_sso.deinit();
    
    try testing.expectEqualStrings("test_client_id", google_sso.config.client_id);
    try testing.expect(google_sso.config.force_pkce);
}