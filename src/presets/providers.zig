//! Common SSO provider presets for easy integration
//! Pre-configured settings for popular identity providers

const std = @import("std");
const root = @import("../root.zig");

/// Common OAuth2/OIDC provider configurations
pub const ProviderPreset = struct {
    name: []const u8,
    issuer_url: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    userinfo_endpoint: ?[]const u8 = null,
    jwks_uri: []const u8,
    scopes: []const []const u8,
    
    /// Convert preset to ZID Config with client credentials
    pub fn toConfig(self: ProviderPreset, allocator: std.mem.Allocator, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !root.Config {
        // Duplicate scopes
        var scopes = try allocator.alloc([]const u8, self.scopes.len);
        for (self.scopes, 0..) |scope, i| {
            scopes[i] = try allocator.dupe(u8, scope);
        }
        
        return root.Config{
            .client_id = try allocator.dupe(u8, client_id),
            .client_secret = if (client_secret) |cs| try allocator.dupe(u8, cs) else null,
            .redirect_uri = try allocator.dupe(u8, redirect_uri),
            .scopes = scopes,
            .issuer_url = try allocator.dupe(u8, self.issuer_url),
            .audience = null,
            
            // Secure defaults
            .enforce_https = true,
            .allow_insecure_http = false,
            .clock_skew_seconds = 300,
            .force_pkce = true,
            .pkce_method = .S256,
            .session_timeout_seconds = 3600,
            .refresh_token_rotation = true,
        };
    }
};

/// Google OAuth2 / OIDC
pub const Google = ProviderPreset{
    .name = "Google",
    .issuer_url = "https://accounts.google.com",
    .authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth",
    .token_endpoint = "https://oauth2.googleapis.com/token",
    .userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo",
    .jwks_uri = "https://www.googleapis.com/oauth2/v3/certs",
    .scopes = &.{"openid", "profile", "email"},
};

/// Microsoft Azure AD / Entra ID
pub const AzureAD = struct {
    pub fn preset(tenant_id: []const u8, allocator: std.mem.Allocator) !ProviderPreset {
        const issuer = try std.fmt.allocPrint(allocator, "https://login.microsoftonline.com/{s}/v2.0", .{tenant_id});
        const auth_endpoint = try std.fmt.allocPrint(allocator, "https://login.microsoftonline.com/{s}/oauth2/v2.0/authorize", .{tenant_id});
        const token_endpoint = try std.fmt.allocPrint(allocator, "https://login.microsoftonline.com/{s}/oauth2/v2.0/token", .{tenant_id});
        const jwks_uri = try std.fmt.allocPrint(allocator, "https://login.microsoftonline.com/{s}/discovery/v2.0/keys", .{tenant_id});
        
        return ProviderPreset{
            .name = "Azure AD",
            .issuer_url = issuer,
            .authorization_endpoint = auth_endpoint,
            .token_endpoint = token_endpoint,
            .userinfo_endpoint = "https://graph.microsoft.com/oidc/userinfo",
            .jwks_uri = jwks_uri,
            .scopes = &.{"openid", "profile", "email"},
        };
    }
};

/// GitHub OAuth2
pub const GitHub = ProviderPreset{
    .name = "GitHub",
    .issuer_url = "https://github.com",
    .authorization_endpoint = "https://github.com/login/oauth/authorize",
    .token_endpoint = "https://github.com/login/oauth/access_token",
    .userinfo_endpoint = "https://api.github.com/user",
    .jwks_uri = "https://token.actions.githubusercontent.com/.well-known/jwks", // For GitHub OIDC
    .scopes = &.{"user:email", "read:user"},
};

/// Auth0
pub const Auth0 = struct {
    pub fn preset(domain: []const u8, allocator: std.mem.Allocator) !ProviderPreset {
        const issuer = try std.fmt.allocPrint(allocator, "https://{s}", .{domain});
        const auth_endpoint = try std.fmt.allocPrint(allocator, "https://{s}/authorize", .{domain});
        const token_endpoint = try std.fmt.allocPrint(allocator, "https://{s}/oauth/token", .{domain});
        const userinfo_endpoint = try std.fmt.allocPrint(allocator, "https://{s}/userinfo", .{domain});
        const jwks_uri = try std.fmt.allocPrint(allocator, "https://{s}/.well-known/jwks.json", .{domain});
        
        return ProviderPreset{
            .name = "Auth0",
            .issuer_url = issuer,
            .authorization_endpoint = auth_endpoint,
            .token_endpoint = token_endpoint,
            .userinfo_endpoint = userinfo_endpoint,
            .jwks_uri = jwks_uri,
            .scopes = &.{"openid", "profile", "email"},
        };
    }
};

/// Okta
pub const Okta = struct {
    pub fn preset(domain: []const u8, allocator: std.mem.Allocator) !ProviderPreset {
        const issuer = try std.fmt.allocPrint(allocator, "https://{s}", .{domain});
        const auth_endpoint = try std.fmt.allocPrint(allocator, "https://{s}/oauth2/default/v1/authorize", .{domain});
        const token_endpoint = try std.fmt.allocPrint(allocator, "https://{s}/oauth2/default/v1/token", .{domain});
        const userinfo_endpoint = try std.fmt.allocPrint(allocator, "https://{s}/oauth2/default/v1/userinfo", .{domain});
        const jwks_uri = try std.fmt.allocPrint(allocator, "https://{s}/oauth2/default/v1/keys", .{domain});
        
        return ProviderPreset{
            .name = "Okta",
            .issuer_url = issuer,
            .authorization_endpoint = auth_endpoint,
            .token_endpoint = token_endpoint,
            .userinfo_endpoint = userinfo_endpoint,
            .jwks_uri = jwks_uri,
            .scopes = &.{"openid", "profile", "email"},
        };
    }
};

/// Keycloak
pub const Keycloak = struct {
    pub fn preset(server_url: []const u8, realm: []const u8, allocator: std.mem.Allocator) !ProviderPreset {
        const issuer = try std.fmt.allocPrint(allocator, "{s}/realms/{s}", .{ server_url, realm });
        const auth_endpoint = try std.fmt.allocPrint(allocator, "{s}/realms/{s}/protocol/openid-connect/auth", .{ server_url, realm });
        const token_endpoint = try std.fmt.allocPrint(allocator, "{s}/realms/{s}/protocol/openid-connect/token", .{ server_url, realm });
        const userinfo_endpoint = try std.fmt.allocPrint(allocator, "{s}/realms/{s}/protocol/openid-connect/userinfo", .{ server_url, realm });
        const jwks_uri = try std.fmt.allocPrint(allocator, "{s}/realms/{s}/protocol/openid-connect/certs", .{ server_url, realm });
        
        return ProviderPreset{
            .name = "Keycloak",
            .issuer_url = issuer,
            .authorization_endpoint = auth_endpoint,
            .token_endpoint = token_endpoint,
            .userinfo_endpoint = userinfo_endpoint,
            .jwks_uri = jwks_uri,
            .scopes = &.{"openid", "profile", "email"},
        };
    }
};

/// Cognito
pub const Cognito = struct {
    pub fn preset(region: []const u8, user_pool_id: []const u8, allocator: std.mem.Allocator) !ProviderPreset {
        const domain = try std.fmt.allocPrint(allocator, "cognito-idp.{s}.amazonaws.com/{s}", .{ region, user_pool_id });
        const issuer = try std.fmt.allocPrint(allocator, "https://{s}", .{domain});
        const auth_endpoint = try std.fmt.allocPrint(allocator, "https://{s}.auth.{s}.amazoncognito.com/oauth2/authorize", .{ user_pool_id, region });
        const token_endpoint = try std.fmt.allocPrint(allocator, "https://{s}.auth.{s}.amazoncognito.com/oauth2/token", .{ user_pool_id, region });
        const userinfo_endpoint = try std.fmt.allocPrint(allocator, "https://{s}.auth.{s}.amazoncognito.com/oauth2/userInfo", .{ user_pool_id, region });
        const jwks_uri = try std.fmt.allocPrint(allocator, "https://cognito-idp.{s}.amazonaws.com/{s}/.well-known/jwks.json", .{ region, user_pool_id });
        
        return ProviderPreset{
            .name = "AWS Cognito",
            .issuer_url = issuer,
            .authorization_endpoint = auth_endpoint,
            .token_endpoint = token_endpoint,
            .userinfo_endpoint = userinfo_endpoint,
            .jwks_uri = jwks_uri,
            .scopes = &.{"openid", "profile", "email"},
        };
    }
};

/// Discord OAuth2
pub const Discord = ProviderPreset{
    .name = "Discord",
    .issuer_url = "https://discord.com",
    .authorization_endpoint = "https://discord.com/api/oauth2/authorize",
    .token_endpoint = "https://discord.com/api/oauth2/token",
    .userinfo_endpoint = "https://discord.com/api/users/@me",
    .jwks_uri = "https://discord.com/api/oauth2/keys", // Placeholder - Discord doesn't use OIDC
    .scopes = &.{"identify", "email"},
};

/// LinkedIn OAuth2
pub const LinkedIn = ProviderPreset{
    .name = "LinkedIn",
    .issuer_url = "https://www.linkedin.com",
    .authorization_endpoint = "https://www.linkedin.com/oauth/v2/authorization",
    .token_endpoint = "https://www.linkedin.com/oauth/v2/accessToken",
    .userinfo_endpoint = "https://api.linkedin.com/v2/userinfo",
    .jwks_uri = "https://www.linkedin.com/oauth/openid_configuration", // Placeholder
    .scopes = &.{"r_liteprofile", "r_emailaddress"},
};

/// Helper functions for quick setup
pub const QuickSetup = struct {
    /// Create Google SSO configuration
    pub fn google(allocator: std.mem.Allocator, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !root.Config {
        return try Google.toConfig(allocator, client_id, client_secret, redirect_uri);
    }
    
    /// Create Azure AD SSO configuration
    pub fn azureAD(allocator: std.mem.Allocator, tenant_id: []const u8, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !root.Config {
        const preset = try AzureAD.preset(tenant_id, allocator);
        return try preset.toConfig(allocator, client_id, client_secret, redirect_uri);
    }
    
    /// Create GitHub SSO configuration
    pub fn github(allocator: std.mem.Allocator, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !root.Config {
        return try GitHub.toConfig(allocator, client_id, client_secret, redirect_uri);
    }
    
    /// Create Auth0 SSO configuration
    pub fn auth0(allocator: std.mem.Allocator, domain: []const u8, client_id: []const u8, client_secret: ?[]const u8, redirect_uri: []const u8) !root.Config {
        const preset = try Auth0.preset(domain, allocator);
        return try preset.toConfig(allocator, client_id, client_secret, redirect_uri);
    }
};

test "provider presets" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Google preset
    const google_config = try QuickSetup.google(
        allocator,
        "test_client_id",
        "test_client_secret",
        "https://example.com/callback"
    );
    defer {
        allocator.free(google_config.client_id);
        if (google_config.client_secret) |cs| allocator.free(cs);
        allocator.free(google_config.redirect_uri);
        allocator.free(google_config.issuer_url);
        for (google_config.scopes) |scope| {
            allocator.free(scope);
        }
        allocator.free(google_config.scopes);
    }
    
    try testing.expectEqualStrings("test_client_id", google_config.client_id);
    try testing.expectEqualStrings("https://accounts.google.com", google_config.issuer_url);
    try testing.expect(google_config.force_pkce);
}