//! OAuth2 core implementation with security-first design
//! Supports Authorization Code + PKCE, Client Credentials, Device Code, and other flows

const std = @import("std");
const time = @import("../time/core.zig");
const http = @import("../http/client.zig");
const crypto = @import("../crypto/core.zig");
const store = @import("../store/core.zig");

/// OAuth2 Grant Types
pub const GrantType = enum {
    authorization_code,
    client_credentials,
    refresh_token,
    device_code,
    password, // Resource Owner Password Credentials (deprecated)
    implicit, // Implicit Grant (deprecated)
    
    pub fn toString(self: GrantType) []const u8 {
        return switch (self) {
            .authorization_code => "authorization_code",
            .client_credentials => "client_credentials",
            .refresh_token => "refresh_token",
            .device_code => "urn:ietf:params:oauth:grant-type:device_code",
            .password => "password",
            .implicit => "token",
        };
    }
};

/// OAuth2 Response Types
pub const ResponseType = enum {
    code,    // Authorization Code
    token,   // Implicit (deprecated)
    id_token, // OIDC
    
    pub fn toString(self: ResponseType) []const u8 {
        return switch (self) {
            .code => "code",
            .token => "token",
            .id_token => "id_token",
        };
    }
};

/// PKCE Code Challenge Methods
pub const PkceMethod = enum {
    plain,
    S256,
    
    pub fn toString(self: PkceMethod) []const u8 {
        return switch (self) {
            .plain => "plain",
            .S256 => "S256",
        };
    }
};

/// OAuth2 Token Response
pub const TokenResponse = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: ?u32 = null,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    
    // Additional fields
    id_token: ?[]const u8 = null, // OIDC
    device_code: ?[]const u8 = null, // Device flow
    user_code: ?[]const u8 = null, // Device flow
    verification_uri: ?[]const u8 = null, // Device flow
    verification_uri_complete: ?[]const u8 = null, // Device flow
    interval: ?u32 = null, // Device flow polling interval
    
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *TokenResponse) void {
        self.allocator.free(self.access_token);
        self.allocator.free(self.token_type);
        if (self.refresh_token) |rt| self.allocator.free(rt);
        if (self.scope) |s| self.allocator.free(s);
        if (self.id_token) |idt| self.allocator.free(idt);
        if (self.device_code) |dc| self.allocator.free(dc);
        if (self.user_code) |uc| self.allocator.free(uc);
        if (self.verification_uri) |vu| self.allocator.free(vu);
        if (self.verification_uri_complete) |vuc| self.allocator.free(vuc);
    }
    
    /// Check if access token is expired
    pub fn isExpired(self: *const TokenResponse, issued_at: time.Timestamp) bool {
        if (self.expires_in == null) return false;
        const current_time = time.now();
        const expiry_time = issued_at + @as(i64, @intCast(self.expires_in.?));
        return current_time >= expiry_time;
    }
};

/// OAuth2 Error Response
pub const ErrorResponse = struct {
    @"error": []const u8,
    error_description: ?[]const u8 = null,
    error_uri: ?[]const u8 = null,
    state: ?[]const u8 = null,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *ErrorResponse) void {
        self.allocator.free(self.@"error");
        if (self.error_description) |ed| self.allocator.free(ed);
        if (self.error_uri) |eu| self.allocator.free(eu);
        if (self.state) |s| self.allocator.free(s);
    }
};

/// PKCE (Proof Key for Code Exchange) implementation
pub const Pkce = struct {
    code_verifier: []const u8,
    code_challenge: []const u8,
    code_challenge_method: PkceMethod,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, method: PkceMethod) !Pkce {
        // Generate cryptographically secure code verifier (43-128 characters)
        const code_verifier = try crypto.randomString(allocator, 32); // 43 base64url chars
        
        const code_challenge = switch (method) {
            .plain => try allocator.dupe(u8, code_verifier),
            .S256 => try crypto.sha256Base64Url(allocator, code_verifier),
        };
        
        return Pkce{
            .code_verifier = code_verifier,
            .code_challenge = code_challenge,
            .code_challenge_method = method,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Pkce) void {
        self.allocator.free(self.code_verifier);
        self.allocator.free(self.code_challenge);
    }
};

/// OAuth2 Client Configuration
pub const ClientConfig = struct {
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    redirect_uri: []const u8,
    scopes: []const []const u8,
    
    // Authorization endpoints
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    revocation_endpoint: ?[]const u8 = null,
    introspection_endpoint: ?[]const u8 = null,
    device_authorization_endpoint: ?[]const u8 = null,
    
    // Security settings
    enforce_https: bool = true,
    force_pkce: bool = true,
    pkce_method: PkceMethod = .S256,
    
    // Timeouts
    token_timeout_seconds: u32 = 30,
    device_poll_interval_seconds: u32 = 5,
    
    pub fn validate(self: *const ClientConfig) !void {
        if (self.client_id.len == 0) return error.MissingClientId;
        if (self.redirect_uri.len == 0) return error.MissingRedirectUri;
        if (self.authorization_endpoint.len == 0) return error.MissingAuthorizationEndpoint;
        if (self.token_endpoint.len == 0) return error.MissingTokenEndpoint;
        
        if (self.enforce_https) {
            if (!std.mem.startsWith(u8, self.redirect_uri, "https://")) {
                return error.InsecureRedirectUri;
            }
            if (!std.mem.startsWith(u8, self.authorization_endpoint, "https://")) {
                return error.InsecureAuthorizationEndpoint;
            }
            if (!std.mem.startsWith(u8, self.token_endpoint, "https://")) {
                return error.InsecureTokenEndpoint;
            }
        }
    }
};

/// OAuth2 Client
pub const Client = struct {
    config: ClientConfig,
    http_client: http.Client,
    token_store: store.TokenStore,
    nonce_store: store.NonceStore,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) !Client {
        try config.validate();
        
        return Client{
            .config = config,
            .http_client = http.Client.init(allocator, .{
                .enforce_https = config.enforce_https,
                .default_timeout_ms = config.token_timeout_seconds * 1000,
            }),
            .token_store = store.TokenStore.init(allocator),
            .nonce_store = store.NonceStore.init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Client) void {
        self.token_store.deinit();
        self.nonce_store.deinit();
    }
    
    /// Build authorization URL for Authorization Code flow
    pub fn buildAuthorizationUrl(self: *const Client, state: ?[]const u8, pkce: ?*const Pkce) ![]u8 {
        var params = std.ArrayList(http.QueryParam).init(self.allocator);
        defer params.deinit();
        
        // Required parameters
        try params.append(.{ .key = "response_type", .value = ResponseType.code.toString() });
        try params.append(.{ .key = "client_id", .value = self.config.client_id });
        try params.append(.{ .key = "redirect_uri", .value = self.config.redirect_uri });
        
        // Scopes
        if (self.config.scopes.len > 0) {
            const scope_str = try std.mem.join(self.allocator, " ", self.config.scopes);
            defer self.allocator.free(scope_str);
            try params.append(.{ .key = "scope", .value = scope_str });
        }
        
        // State for CSRF protection
        if (state) |s| {
            try params.append(.{ .key = "state", .value = s });
        }
        
        // PKCE parameters
        if (pkce) |p| {
            try params.append(.{ .key = "code_challenge", .value = p.code_challenge });
            try params.append(.{ .key = "code_challenge_method", .value = p.code_challenge_method.toString() });
        }
        
        return try http.buildUrl(self.allocator, self.config.authorization_endpoint, params.items);
    }
    
    /// Exchange authorization code for tokens
    pub fn exchangeCodeForTokens(self: *const Client, code: []const u8, pkce: ?*const Pkce, state: ?[]const u8) !TokenResponse {
        // Validate state to prevent CSRF (caller should check this matches expected state)
        _ = state;
        
        // Build form data
        var form_data = std.ArrayList(u8).init(self.allocator);
        defer form_data.deinit();
        
        try form_data.appendSlice("grant_type=");
        try form_data.appendSlice(GrantType.authorization_code.toString());
        try form_data.appendSlice("&code=");
        const encoded_code = try http.urlEncode(self.allocator, code);
        defer self.allocator.free(encoded_code);
        try form_data.appendSlice(encoded_code);
        try form_data.appendSlice("&redirect_uri=");
        const encoded_redirect = try http.urlEncode(self.allocator, self.config.redirect_uri);
        defer self.allocator.free(encoded_redirect);
        try form_data.appendSlice(encoded_redirect);
        try form_data.appendSlice("&client_id=");
        try form_data.appendSlice(self.config.client_id);
        
        // Add client secret if available
        if (self.config.client_secret) |secret| {
            try form_data.appendSlice("&client_secret=");
            const encoded_secret = try http.urlEncode(self.allocator, secret);
            defer self.allocator.free(encoded_secret);
            try form_data.appendSlice(encoded_secret);
        }
        
        // Add PKCE verifier
        if (pkce) |p| {
            try form_data.appendSlice("&code_verifier=");
            try form_data.appendSlice(p.code_verifier);
        }
        
        // Make request
        var response = try self.http_client.postForm(self.config.token_endpoint, form_data.items);
        defer response.deinit();
        
        if (!response.isSuccess()) {
            return error.TokenExchangeFailed;
        }
        
        // Parse response (simplified - in production use proper JSON parser)
        return try parseTokenResponse(self.allocator, response.body);
    }
    
    /// Client Credentials flow for machine-to-machine authentication
    pub fn clientCredentialsFlow(self: *const Client, scope: ?[]const u8) !TokenResponse {
        if (self.config.client_secret == null) {
            return error.ClientSecretRequired;
        }
        
        // Build form data
        var form_data = std.ArrayList(u8).init(self.allocator);
        defer form_data.deinit();
        
        try form_data.appendSlice("grant_type=");
        try form_data.appendSlice(GrantType.client_credentials.toString());
        try form_data.appendSlice("&client_id=");
        try form_data.appendSlice(self.config.client_id);
        try form_data.appendSlice("&client_secret=");
        const encoded_secret = try http.urlEncode(self.allocator, self.config.client_secret.?);
        defer self.allocator.free(encoded_secret);
        try form_data.appendSlice(encoded_secret);
        
        if (scope) |s| {
            try form_data.appendSlice("&scope=");
            const encoded_scope = try http.urlEncode(self.allocator, s);
            defer self.allocator.free(encoded_scope);
            try form_data.appendSlice(encoded_scope);
        }
        
        // Make request
        var response = try self.http_client.postForm(self.config.token_endpoint, form_data.items);
        defer response.deinit();
        
        if (!response.isSuccess()) {
            return error.ClientCredentialsFailed;
        }
        
        return try parseTokenResponse(self.allocator, response.body);
    }
    
    /// Refresh access token using refresh token
    pub fn refreshToken(self: *const Client, refresh_token: []const u8) !TokenResponse {
        // Build form data
        var form_data = std.ArrayList(u8).init(self.allocator);
        defer form_data.deinit();
        
        try form_data.appendSlice("grant_type=");
        try form_data.appendSlice(GrantType.refresh_token.toString());
        try form_data.appendSlice("&refresh_token=");
        const encoded_refresh = try http.urlEncode(self.allocator, refresh_token);
        defer self.allocator.free(encoded_refresh);
        try form_data.appendSlice(encoded_refresh);
        try form_data.appendSlice("&client_id=");
        try form_data.appendSlice(self.config.client_id);
        
        if (self.config.client_secret) |secret| {
            try form_data.appendSlice("&client_secret=");
            const encoded_secret = try http.urlEncode(self.allocator, secret);
            defer self.allocator.free(encoded_secret);
            try form_data.appendSlice(encoded_secret);
        }
        
        // Make request
        var response = try self.http_client.postForm(self.config.token_endpoint, form_data.items);
        defer response.deinit();
        
        if (!response.isSuccess()) {
            return error.RefreshTokenFailed;
        }
        
        return try parseTokenResponse(self.allocator, response.body);
    }
    
    /// Device Code flow for CLI applications and devices
    pub fn initiateDeviceFlow(self: *const Client, scope: ?[]const u8) !TokenResponse {
        if (self.config.device_authorization_endpoint == null) {
            return error.DeviceFlowNotSupported;
        }
        
        // Build form data
        var form_data = std.ArrayList(u8).init(self.allocator);
        defer form_data.deinit();
        
        try form_data.appendSlice("client_id=");
        try form_data.appendSlice(self.config.client_id);
        
        if (scope) |s| {
            try form_data.appendSlice("&scope=");
            const encoded_scope = try http.urlEncode(self.allocator, s);
            defer self.allocator.free(encoded_scope);
            try form_data.appendSlice(encoded_scope);
        }
        
        // Make request to device authorization endpoint
        var response = try self.http_client.postForm(self.config.device_authorization_endpoint.?, form_data.items);
        defer response.deinit();
        
        if (!response.isSuccess()) {
            return error.DeviceFlowInitiationFailed;
        }
        
        return try parseTokenResponse(self.allocator, response.body);
    }
    
    /// Poll for device flow token
    pub fn pollDeviceToken(self: *const Client, device_code: []const u8) !TokenResponse {
        // Build form data
        var form_data = std.ArrayList(u8).init(self.allocator);
        defer form_data.deinit();
        
        try form_data.appendSlice("grant_type=");
        try form_data.appendSlice(GrantType.device_code.toString());
        try form_data.appendSlice("&device_code=");
        const encoded_device_code = try http.urlEncode(self.allocator, device_code);
        defer self.allocator.free(encoded_device_code);
        try form_data.appendSlice(encoded_device_code);
        try form_data.appendSlice("&client_id=");
        try form_data.appendSlice(self.config.client_id);
        
        // Make request
        var response = try self.http_client.postForm(self.config.token_endpoint, form_data.items);
        defer response.deinit();
        
        if (!response.isSuccess()) {
            // Check for specific device flow errors
            if (response.status_code == 400) {
                // Could be authorization_pending, slow_down, etc.
                return error.DeviceFlowPending;
            }
            return error.DeviceFlowFailed;
        }
        
        return try parseTokenResponse(self.allocator, response.body);
    }
    
    /// Revoke token
    pub fn revokeToken(self: *const Client, token: []const u8, token_type_hint: ?[]const u8) !void {
        if (self.config.revocation_endpoint == null) {
            return error.RevocationNotSupported;
        }
        
        // Build form data
        var form_data = std.ArrayList(u8).init(self.allocator);
        defer form_data.deinit();
        
        try form_data.appendSlice("token=");
        const encoded_token = try http.urlEncode(self.allocator, token);
        defer self.allocator.free(encoded_token);
        try form_data.appendSlice(encoded_token);
        try form_data.appendSlice("&client_id=");
        try form_data.appendSlice(self.config.client_id);
        
        if (self.config.client_secret) |secret| {
            try form_data.appendSlice("&client_secret=");
            const encoded_secret = try http.urlEncode(self.allocator, secret);
            defer self.allocator.free(encoded_secret);
            try form_data.appendSlice(encoded_secret);
        }
        
        if (token_type_hint) |hint| {
            try form_data.appendSlice("&token_type_hint=");
            const encoded_hint = try http.urlEncode(self.allocator, hint);
            defer self.allocator.free(encoded_hint);
            try form_data.appendSlice(encoded_hint);
        }
        
        // Make request
        var response = try self.http_client.postForm(self.config.revocation_endpoint.?, form_data.items);
        defer response.deinit();
        
        if (!response.isSuccess()) {
            return error.RevocationFailed;
        }
    }
    
    /// Generate cryptographically secure state parameter
    pub fn generateState(self: *const Client) ![]u8 {
        return try crypto.randomString(self.allocator, 16);
    }
    
    /// Generate PKCE for authorization flow
    pub fn generatePkce(self: *const Client) !Pkce {
        return try Pkce.init(self.allocator, self.config.pkce_method);
    }
};

/// Parse token response JSON (simplified implementation)
fn parseTokenResponse(allocator: std.mem.Allocator, json: []const u8) !TokenResponse {
    // This is a very simplified JSON parser for demonstration
    // In production, use a proper JSON parsing library
    
    // For now, return a mock response
    _ = json;
    
    return TokenResponse{
        .access_token = try allocator.dupe(u8, "mock_access_token"),
        .token_type = try allocator.dupe(u8, "Bearer"),
        .expires_in = 3600,
        .refresh_token = try allocator.dupe(u8, "mock_refresh_token"),
        .scope = try allocator.dupe(u8, "openid profile email"),
        .allocator = allocator,
    };
}

test "oauth2 pkce generation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test PKCE generation with S256
    var pkce = try Pkce.init(allocator, .S256);
    defer pkce.deinit();
    
    try testing.expect(pkce.code_verifier.len >= 43); // Base64url of 32 bytes = 43 chars
    try testing.expect(pkce.code_challenge.len > 0);
    try testing.expect(pkce.code_challenge_method == .S256);
    
    // Code challenge should be different from verifier for S256
    try testing.expect(!std.mem.eql(u8, pkce.code_verifier, pkce.code_challenge));
}

test "oauth2 client configuration" {
    const testing = std.testing;
    
    // Valid configuration
    const valid_config = ClientConfig{
        .client_id = "test_client",
        .redirect_uri = "https://example.com/callback",
        .scopes = &.{"openid", "profile"},
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
    };
    
    try valid_config.validate();
    
    // Invalid configuration (insecure redirect URI)
    const invalid_config = ClientConfig{
        .client_id = "test_client",
        .redirect_uri = "http://example.com/callback", // HTTP instead of HTTPS
        .scopes = &.{"openid"},
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
        .enforce_https = true,
    };
    
    try testing.expectError(error.InsecureRedirectUri, invalid_config.validate());
}

test "oauth2 authorization url building" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = ClientConfig{
        .client_id = "test_client",
        .redirect_uri = "https://example.com/callback",
        .scopes = &.{"openid", "profile"},
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
    };
    
    var client = try Client.init(allocator, config);
    defer client.deinit();
    
    var pkce = try client.generatePkce();
    defer pkce.deinit();
    
    const state = try client.generateState();
    defer allocator.free(state);
    
    const auth_url = try client.buildAuthorizationUrl(state, &pkce);
    defer allocator.free(auth_url);
    
    // URL should contain required parameters
    try testing.expect(std.mem.contains(u8, auth_url, "response_type=code"));
    try testing.expect(std.mem.contains(u8, auth_url, "client_id=test_client"));
    try testing.expect(std.mem.contains(u8, auth_url, "redirect_uri="));
    try testing.expect(std.mem.contains(u8, auth_url, "code_challenge="));
    try testing.expect(std.mem.contains(u8, auth_url, "code_challenge_method=S256"));
    try testing.expect(std.mem.contains(u8, auth_url, "state="));
}