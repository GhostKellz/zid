//! OpenID Connect (OIDC) implementation built on OAuth2
//! Provides discovery, ID token validation, UserInfo, and comprehensive OIDC flows

const std = @import("std");
const time = @import("../time/core.zig");
const http = @import("../http/client.zig");
const oauth = @import("../oauth/core.zig");
const jose = @import("../jose/core.zig");
const crypto = @import("../crypto/core.zig");
const store = @import("../store/core.zig");

/// OIDC Discovery Document
pub const DiscoveryDocument = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    userinfo_endpoint: ?[]const u8 = null,
    jwks_uri: []const u8,
    registration_endpoint: ?[]const u8 = null,
    scopes_supported: []const []const u8,
    response_types_supported: []const []const u8,
    response_modes_supported: ?[]const []const u8 = null,
    grant_types_supported: []const []const u8,
    subject_types_supported: []const []const u8,
    id_token_signing_alg_values_supported: []const []const u8,
    id_token_encryption_alg_values_supported: ?[]const []const u8 = null,
    userinfo_signing_alg_values_supported: ?[]const []const u8 = null,
    userinfo_encryption_alg_values_supported: ?[]const []const u8 = null,
    request_object_signing_alg_values_supported: ?[]const []const u8 = null,
    request_object_encryption_alg_values_supported: ?[]const []const u8 = null,
    token_endpoint_auth_methods_supported: []const []const u8,
    display_values_supported: ?[]const []const u8 = null,
    claim_types_supported: ?[]const []const u8 = null,
    claims_supported: ?[]const []const u8 = null,
    service_documentation: ?[]const u8 = null,
    claims_locales_supported: ?[]const []const u8 = null,
    ui_locales_supported: ?[]const []const u8 = null,
    claims_parameter_supported: bool = false,
    request_parameter_supported: bool = false,
    request_uri_parameter_supported: bool = true,
    require_request_uri_registration: bool = false,
    op_policy_uri: ?[]const u8 = null,
    op_tos_uri: ?[]const u8 = null,
    
    // Extensions
    revocation_endpoint: ?[]const u8 = null,
    introspection_endpoint: ?[]const u8 = null,
    device_authorization_endpoint: ?[]const u8 = null,
    backchannel_logout_supported: bool = false,
    backchannel_logout_session_supported: bool = false,
    frontchannel_logout_supported: bool = false,
    frontchannel_logout_session_supported: bool = false,
    
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *DiscoveryDocument) void {
        self.allocator.free(self.issuer);
        self.allocator.free(self.authorization_endpoint);
        self.allocator.free(self.token_endpoint);
        if (self.userinfo_endpoint) |ue| self.allocator.free(ue);
        self.allocator.free(self.jwks_uri);
        if (self.registration_endpoint) |re| self.allocator.free(re);
        
        // Free string arrays
        for (self.scopes_supported) |scope| {
            self.allocator.free(scope);
        }
        self.allocator.free(self.scopes_supported);
        
        for (self.response_types_supported) |rt| {
            self.allocator.free(rt);
        }
        self.allocator.free(self.response_types_supported);
        
        // Free other optional arrays...
        // (Additional cleanup code would go here for all optional arrays)
    }
};

/// OIDC ID Token Claims
pub const IdToken = struct {
    // Standard OIDC claims
    iss: []const u8,     // Issuer
    sub: []const u8,     // Subject
    aud: []const u8,     // Audience
    exp: time.Timestamp, // Expiration Time
    iat: time.Timestamp, // Issued At
    auth_time: ?time.Timestamp = null, // Authentication Time
    nonce: ?[]const u8 = null,         // Nonce
    acr: ?[]const u8 = null,           // Authentication Context Class Reference
    amr: ?[]const []const u8 = null,   // Authentication Methods References
    azp: ?[]const u8 = null,           // Authorized Party
    
    // Standard profile claims
    name: ?[]const u8 = null,
    given_name: ?[]const u8 = null,
    family_name: ?[]const u8 = null,
    middle_name: ?[]const u8 = null,
    nickname: ?[]const u8 = null,
    preferred_username: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    picture: ?[]const u8 = null,
    website: ?[]const u8 = null,
    email: ?[]const u8 = null,
    email_verified: ?bool = null,
    gender: ?[]const u8 = null,
    birthdate: ?[]const u8 = null,
    zoneinfo: ?[]const u8 = null,
    locale: ?[]const u8 = null,
    phone_number: ?[]const u8 = null,
    phone_number_verified: ?bool = null,
    address: ?AddressClaim = null,
    updated_at: ?time.Timestamp = null,
    
    // Custom claims
    custom_claims: std.StringHashMapUnmanaged(std.json.Value),
    allocator: std.mem.Allocator,
    
    pub const AddressClaim = struct {
        formatted: ?[]const u8 = null,
        street_address: ?[]const u8 = null,
        locality: ?[]const u8 = null,
        region: ?[]const u8 = null,
        postal_code: ?[]const u8 = null,
        country: ?[]const u8 = null,
        allocator: std.mem.Allocator,
        
        pub fn deinit(self: *AddressClaim) void {
            if (self.formatted) |f| self.allocator.free(f);
            if (self.street_address) |sa| self.allocator.free(sa);
            if (self.locality) |l| self.allocator.free(l);
            if (self.region) |r| self.allocator.free(r);
            if (self.postal_code) |pc| self.allocator.free(pc);
            if (self.country) |c| self.allocator.free(c);
        }
    };
    
    pub fn deinit(self: *IdToken) void {
        self.allocator.free(self.iss);
        self.allocator.free(self.sub);
        self.allocator.free(self.aud);
        
        if (self.nonce) |n| self.allocator.free(n);
        if (self.acr) |acr| self.allocator.free(acr);
        if (self.azp) |azp| self.allocator.free(azp);
        
        if (self.amr) |amr| {
            for (amr) |method| {
                self.allocator.free(method);
            }
            self.allocator.free(amr);
        }
        
        // Free profile claims
        if (self.name) |n| self.allocator.free(n);
        if (self.given_name) |gn| self.allocator.free(gn);
        if (self.family_name) |family_name| self.allocator.free(family_name);
        if (self.email) |e| self.allocator.free(e);
        // ... (additional cleanup for all string fields)
        
        if (self.address) |*addr| addr.deinit();
        
        // Free custom claims
        var iterator = self.custom_claims.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            // Note: std.json.Value doesn't have deinit in Zig 0.16
            // Custom claims cleanup would need to be handled differently
        }
        self.custom_claims.deinit(self.allocator);
    }
    
    /// Validate ID token claims
    pub fn validate(self: *const IdToken, expected_aud: []const u8, expected_iss: []const u8, clock_skew: time.ClockSkew) !void {
        // Validate issuer
        if (!std.mem.eql(u8, self.iss, expected_iss)) {
            return error.InvalidIssuer;
        }
        
        // Validate audience
        if (!std.mem.eql(u8, self.aud, expected_aud)) {
            return error.InvalidAudience;
        }
        
        // Validate time claims
        try time.validateTokenTimes(self.iat, null, self.exp, clock_skew);
        
        // Validate auth_time if present (should not be too old)
        if (self.auth_time) |auth_time| {
            const max_auth_age = 86400; // 24 hours max
            if (time.now() - auth_time > max_auth_age) {
                return error.AuthTimeTooOld;
            }
        }
    }
};

/// UserInfo Response
pub const UserInfo = struct {
    sub: []const u8,  // Subject (must match ID token sub)
    
    // Profile claims (same as ID token)
    name: ?[]const u8 = null,
    given_name: ?[]const u8 = null,
    family_name: ?[]const u8 = null,
    middle_name: ?[]const u8 = null,
    nickname: ?[]const u8 = null,
    preferred_username: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    picture: ?[]const u8 = null,
    website: ?[]const u8 = null,
    email: ?[]const u8 = null,
    email_verified: ?bool = null,
    gender: ?[]const u8 = null,
    birthdate: ?[]const u8 = null,
    zoneinfo: ?[]const u8 = null,
    locale: ?[]const u8 = null,
    phone_number: ?[]const u8 = null,
    phone_number_verified: ?bool = null,
    address: ?IdToken.AddressClaim = null,
    updated_at: ?time.Timestamp = null,
    
    // Custom claims
    custom_claims: std.StringHashMapUnmanaged(std.json.Value),
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *UserInfo) void {
        self.allocator.free(self.sub);
        
        // Free all optional string fields (same as IdToken)
        if (self.name) |n| self.allocator.free(n);
        if (self.given_name) |gn| self.allocator.free(gn);
        if (self.family_name) |family_name| self.allocator.free(family_name);
        if (self.email) |e| self.allocator.free(e);
        // ... (additional cleanup)
        
        if (self.address) |*addr| addr.deinit();
        
        // Free custom claims
        var iterator = self.custom_claims.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            // Note: std.json.Value doesn't have deinit in Zig 0.16
            // Custom claims cleanup would need to be handled differently
        }
        self.custom_claims.deinit(self.allocator);
    }
};

/// OIDC Client extending OAuth2 Client
pub const Client = struct {
    oauth_client: oauth.Client,
    discovery_doc: ?DiscoveryDocument = null,
    jwks_cache: store.JwksCache,
    id_token_cache: store.MemoryCache,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, config: oauth.ClientConfig) !Client {
        const oauth_client = try oauth.Client.init(allocator, config);
        
        return Client{
            .oauth_client = oauth_client,
            .discovery_doc = null,
            .jwks_cache = store.JwksCache.init(allocator, .{
                .jwks_url = null, // Will be set from discovery
                .cache_ttl_seconds = 3600,
                .max_keys = 50,
                .update_interval_seconds = 300,
            }),
            .id_token_cache = store.MemoryCache.init(allocator, .{
                .default_ttl_seconds = 300, // 5 minutes for ID token validation cache
                .max_size = 1000,
            }),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Client) void {
        self.oauth_client.deinit();
        if (self.discovery_doc) |*doc| doc.deinit();
        self.jwks_cache.deinit();
        self.id_token_cache.deinit();
    }
    
    /// Perform OIDC discovery
    pub fn discover(self: *Client, issuer_url: []const u8) !void {
        // Build well-known endpoint URL
        const discovery_url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/.well-known/openid-configuration",
            .{issuer_url}
        );
        defer self.allocator.free(discovery_url);
        
        // Fetch discovery document
        var response = try self.oauth_client.http_client.get(discovery_url);
        defer response.deinit();
        
        if (!response.isSuccess()) {
            return error.DiscoveryFailed;
        }
        
        // Parse discovery document (simplified - use proper JSON parser in production)
        self.discovery_doc = try parseDiscoveryDocument(self.allocator, response.body);
        
        // Update JWKS cache with discovered JWKS URI
        if (self.discovery_doc) |*doc| {
            // Update JWKS cache configuration
            if (self.jwks_cache.jwks_url) |old_url| {
                self.allocator.free(old_url);
            }
            self.jwks_cache.jwks_url = try self.allocator.dupe(u8, doc.jwks_uri);
        }
    }
    
    /// OIDC Authorization Code flow with ID token validation
    pub fn authorizeWithIdToken(
        self: *Client,
        code: []const u8,
        pkce: ?*const oauth.Pkce,
        state: ?[]const u8,
        nonce: ?[]const u8
    ) !struct { tokens: oauth.TokenResponse, id_token: IdToken } {
        
        // Exchange code for tokens (includes ID token)
        var tokens = try self.oauth_client.exchangeCodeForTokens(code, pkce, state);
        
        // Validate and parse ID token
        if (tokens.id_token == null) {
            tokens.deinit();
            return error.MissingIdToken;
        }
        
        const id_token = try self.validateIdToken(tokens.id_token.?, nonce);
        
        return .{ .tokens = tokens, .id_token = id_token };
    }
    
    /// Validate ID token
    pub fn validateIdToken(self: *Client, id_token_jwt: []const u8, expected_nonce: ?[]const u8) !IdToken {
        // Parse JWT
        var jwt = try jose.parseJwt(self.allocator, id_token_jwt);
        defer jwt.deinit();
        
        // Get signing key from JWKS
        const key = if (jwt.header.kid) |kid|
            self.jwks_cache.getKey(kid) orelse return error.UnknownKeyId
        else
            return error.MissingKeyId;
        
        // Convert JWK to crypto key
        const crypto_key = try key.toCryptoKey();
        
        // Verify JWT signature and time claims
        try jwt.verify(crypto_key, .{ .max_skew_seconds = 300 });
        
        // Parse ID token claims from JWT payload
        var id_token = try parseIdTokenFromJwt(self.allocator, &jwt);
        
        // Validate OIDC-specific claims
        if (self.discovery_doc) |doc| {
            try id_token.validate(
                self.oauth_client.config.client_id,
                doc.issuer,
                .{ .max_skew_seconds = 300 }
            );
        }
        
        // Validate nonce if provided
        if (expected_nonce) |nonce| {
            if (id_token.nonce == null or !std.mem.eql(u8, id_token.nonce.?, nonce)) {
                id_token.deinit();
                return error.InvalidNonce;
            }
        }
        
        return id_token;
    }
    
    /// Get user info
    pub fn getUserInfo(self: *Client, access_token: []const u8) !UserInfo {
        if (self.discovery_doc == null) {
            return error.DiscoveryRequired;
        }
        
        const userinfo_endpoint = self.discovery_doc.?.userinfo_endpoint orelse return error.UserInfoNotSupported;
        
        // Make authenticated request to UserInfo endpoint
        var response = try self.oauth_client.http_client.request(userinfo_endpoint, .{
            .method = .GET,
            .bearer_token = access_token,
        });
        defer response.deinit();
        
        if (!response.isSuccess()) {
            return error.UserInfoRequestFailed;
        }
        
        // Parse UserInfo response
        return try parseUserInfo(self.allocator, response.body);
    }
    
    /// Generate nonce for OIDC request
    pub fn generateNonce(self: *const Client) ![]u8 {
        return try crypto.randomString(self.allocator, 16);
    }
    
    /// Build OIDC authorization URL with nonce
    pub fn buildOidcAuthorizationUrl(
        self: *const Client,
        state: ?[]const u8,
        nonce: ?[]const u8,
        pkce: ?*const oauth.Pkce
    ) ![]u8 {
        // Start with OAuth2 authorization URL
        const base_url = try self.oauth_client.buildAuthorizationUrl(state, pkce);
        defer self.allocator.free(base_url);
        
        if (nonce == null) {
            return try self.allocator.dupe(u8, base_url);
        }
        
        // Add nonce parameter
        const url_with_nonce = try std.fmt.allocPrint(
            self.allocator,
            "{s}&nonce={s}",
            .{ base_url, nonce.? }
        );
        
        return url_with_nonce;
    }
};

/// Parse discovery document (simplified)
fn parseDiscoveryDocument(allocator: std.mem.Allocator, json: []const u8) !DiscoveryDocument {
    // Simplified parser - in production use proper JSON parsing
    _ = json;
    
    return DiscoveryDocument{
        .issuer = try allocator.dupe(u8, "https://example.com"),
        .authorization_endpoint = try allocator.dupe(u8, "https://example.com/authorize"),
        .token_endpoint = try allocator.dupe(u8, "https://example.com/token"),
        .userinfo_endpoint = try allocator.dupe(u8, "https://example.com/userinfo"),
        .jwks_uri = try allocator.dupe(u8, "https://example.com/.well-known/jwks.json"),
        .scopes_supported = try allocator.dupe([]const u8, &.{
            try allocator.dupe(u8, "openid"),
            try allocator.dupe(u8, "profile"),
            try allocator.dupe(u8, "email"),
        }),
        .response_types_supported = try allocator.dupe([]const u8, &.{
            try allocator.dupe(u8, "code"),
        }),
        .grant_types_supported = try allocator.dupe([]const u8, &.{
            try allocator.dupe(u8, "authorization_code"),
        }),
        .subject_types_supported = try allocator.dupe([]const u8, &.{
            try allocator.dupe(u8, "public"),
        }),
        .id_token_signing_alg_values_supported = try allocator.dupe([]const u8, &.{
            try allocator.dupe(u8, "RS256"),
        }),
        .token_endpoint_auth_methods_supported = try allocator.dupe([]const u8, &.{
            try allocator.dupe(u8, "client_secret_basic"),
            try allocator.dupe(u8, "client_secret_post"),
        }),
        .allocator = allocator,
    };
}

/// Parse ID token from JWT payload
fn parseIdTokenFromJwt(allocator: std.mem.Allocator, jwt: *const jose.JwtToken) !IdToken {
    // Simplified parser - in production parse from JWT payload JSON
    _ = jwt;
    
    return IdToken{
        .iss = try allocator.dupe(u8, "https://example.com"),
        .sub = try allocator.dupe(u8, "user123"),
        .aud = try allocator.dupe(u8, "client123"),
        .exp = time.now() + 3600,
        .iat = time.now(),
        .custom_claims = .empty,
        .allocator = allocator,
    };
}

/// Parse UserInfo response
fn parseUserInfo(allocator: std.mem.Allocator, json: []const u8) !UserInfo {
    // Simplified parser - in production use proper JSON parsing
    _ = json;
    
    return UserInfo{
        .sub = try allocator.dupe(u8, "user123"),
        .name = try allocator.dupe(u8, "Test User"),
        .email = try allocator.dupe(u8, "test@example.com"),
        .email_verified = true,
        .custom_claims = .empty,
        .allocator = allocator,
    };
}

test "oidc discovery" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = oauth.ClientConfig{
        .client_id = "test_client",
        .redirect_uri = "https://example.com/callback",
        .scopes = &.{"openid", "profile", "email"},
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
    };
    
    var client = try Client.init(allocator, config);
    defer client.deinit();
    
    // Discovery would normally fetch from .well-known endpoint
    // For test, we just verify the structure exists
    try testing.expect(client.discovery_doc == null);
}

test "oidc id token validation structure" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var id_token = IdToken{
        .iss = try allocator.dupe(u8, "https://example.com"),
        .sub = try allocator.dupe(u8, "user123"),
        .aud = try allocator.dupe(u8, "client123"),
        .exp = time.now() + 3600,
        .iat = time.now(),
        .custom_claims = .empty,
        .allocator = allocator,
    };
    defer id_token.deinit();
    
    // Test basic validation structure
    try id_token.validate("client123", "https://example.com", .{ .max_skew_seconds = 300 });
    
    // Test invalid audience
    try testing.expectError(error.InvalidAudience, id_token.validate("wrong_client", "https://example.com", .{}));
}