//! ZID - A comprehensive OIDC/OAuth2/SAML library for Zig 0.16-dev
//! 
//! This library provides secure, production-ready implementations of:
//! - OAuth2 flows (Authorization Code + PKCE, Client Credentials, Device Code, etc.)
//! - OpenID Connect (OIDC) with discovery, UserInfo, and ID token validation
//! - SAML 2.0 for enterprise SSO
//! - JOSE (JWT/JWS/JWE/JWK) with comprehensive crypto support
//! - Secure session management and token handling
//!
//! Architecture follows security-first principles with:
//! - Constant-time crypto operations
//! - Algorithm whitelisting and fail-closed design
//! - PKCE, nonce, and state CSRF protection
//! - Secure cookie handling with proper flags
//! - Clock skew tolerance and replay protection

const std = @import("std");

// Core modules
pub const http = @import("http/client.zig");
pub const oauth = @import("oauth/core.zig");
pub const oidc = @import("oidc/core.zig");
pub const jose = @import("jose/core.zig");
pub const crypto = @import("crypto/core.zig");
pub const saml = @import("saml/core.zig");
pub const store = @import("store/core.zig");
pub const time = @import("time/core.zig");

// New integration modules
pub const config = @import("config/env.zig");
pub const presets = @import("presets/providers.zig");
pub const quick = @import("helpers/quick.zig");

// Re-export commonly used types and functions
pub const Client = oauth.Client;
pub const OidcClient = oidc.Client;
pub const TokenResponse = oauth.TokenResponse;
pub const IdToken = oidc.IdToken;
pub const JwtToken = jose.JwtToken;

// Configuration and error types
pub const Config = struct {
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    redirect_uri: []const u8,
    scopes: []const []const u8,
    issuer_url: []const u8,
    audience: ?[]const u8 = null,
    
    // Security settings
    enforce_https: bool = true,
    allow_insecure_http: bool = false,
    clock_skew_seconds: u32 = 300, // 5 minutes
    
    // PKCE settings
    force_pkce: bool = true,
    pkce_method: PkceMethod = .S256,
    
    // Session settings
    session_timeout_seconds: u32 = 3600, // 1 hour
    refresh_token_rotation: bool = true,
};

pub const PkceMethod = enum {
    plain,
    S256,
};

pub const ZidError = error{
    InvalidConfiguration,
    NetworkError,
    InvalidToken,
    TokenExpired,
    InvalidSignature,
    InvalidClaims,
    DiscoveryError,
    AuthorizationError,
    InvalidState,
    InvalidNonce,
    CryptoError,
    TimeError,
    SessionError,
    OutOfMemory,
    InvalidJson,
    InvalidXml,
    SamlError,
    HttpError,
    TlsError,
};

// Async support with zsync (when available)
pub const async_support = @hasDecl(std, "event") or @hasDecl(std, "Thread");

// Convenience functions for easy setup
/// Quick setup from .env file
pub fn setupFromEnv(allocator: std.mem.Allocator) !quick.QuickSSO {
    return try quick.QuickSSO.fromEnv(allocator, ".env");
}

/// Load configuration from .env file
pub fn loadFromEnv(allocator: std.mem.Allocator, env_file_path: ?[]const u8) !Config {
    return try config.loadConfig(allocator, env_file_path);
}

/// Quick Google SSO setup
pub fn setupGoogle(allocator: std.mem.Allocator, client_id: []const u8, client_secret: []const u8, redirect_uri: []const u8) !quick.QuickSSO {
    return try quick.QuickSSO.google(allocator, client_id, client_secret, redirect_uri);
}

/// Quick Azure AD SSO setup
pub fn setupAzureAD(allocator: std.mem.Allocator, tenant_id: []const u8, client_id: []const u8, client_secret: []const u8, redirect_uri: []const u8) !quick.QuickSSO {
    return try quick.QuickSSO.azureAD(allocator, tenant_id, client_id, client_secret, redirect_uri);
}

/// Quick GitHub SSO setup
pub fn setupGitHub(allocator: std.mem.Allocator, client_id: []const u8, client_secret: []const u8, redirect_uri: []const u8) !quick.QuickSSO {
    return try quick.QuickSSO.github(allocator, client_id, client_secret, redirect_uri);
}

test "zid module structure" {
    const testing = std.testing;
    
    // Basic smoke test to ensure modules can be imported
    _ = http;
    _ = oauth;
    _ = oidc;
    _ = jose;
    _ = crypto;
    _ = saml;
    _ = store;
    _ = time;
    
    try testing.expect(true);
}