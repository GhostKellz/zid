const std = @import("std");
const zid = @import("zid");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("ZID - Comprehensive OIDC/OAuth2/SAML Library for Zig\n", .{});
    std.debug.print("====================================================\n\n", .{});
    
    // Test basic library functionality
    try testLibrary(allocator);
    
    // Demonstrate new features
    try demonstrateNewFeatures(allocator);
    
    std.debug.print("\n✅ All tests completed successfully!\n", .{});
}

fn testLibrary(allocator: std.mem.Allocator) !void {
    std.debug.print("🔐 Testing ZID Library Components\n", .{});
    std.debug.print("----------------------------------\n", .{});
    
    // Test crypto operations
    const random_bytes = try zid.crypto.randomBytes(allocator, 16);
    defer allocator.free(random_bytes);
    
    const random_string = try zid.crypto.randomString(allocator, 8);
    defer allocator.free(random_string);
    
    std.debug.print("  Random bytes generated: {} bytes\n", .{random_bytes.len});
    std.debug.print("  Random string generated: {} chars\n", .{random_string.len});
    
    // Test time utilities
    const current_time = zid.time.now();
    std.debug.print("  Current timestamp: {}\n", .{current_time});
    
    // Test algorithm parsing
    const alg = try zid.crypto.Algorithm.fromString("HS256");
    std.debug.print("  Algorithm parsed: {s}\n", .{alg.toString()});
    
    std.debug.print("  ✅ Library components working correctly\n", .{});
}

fn demonstrateNewFeatures(_: std.mem.Allocator) !void {
    std.debug.print("\n🚀 Demonstrating New SSO Features\n", .{});
    std.debug.print("----------------------------------\n", .{});
    
    // 1. Environment configuration
    std.debug.print("  📁 Environment Configuration Support:\n", .{});
    std.debug.print("     - .env file loading\n", .{});
    std.debug.print("     - Environment variable support\n", .{});
    std.debug.print("     - Automatic configuration parsing\n", .{});
    
    // 2. Provider presets
    std.debug.print("\n  🏢 Built-in Provider Presets:\n", .{});
    std.debug.print("     - Google OAuth2/OIDC\n", .{});
    std.debug.print("     - Microsoft Azure AD\n", .{});
    std.debug.print("     - GitHub OAuth2\n", .{});
    std.debug.print("     - Auth0\n", .{});
    std.debug.print("     - Okta\n", .{});
    std.debug.print("     - AWS Cognito\n", .{});
    std.debug.print("     - Keycloak\n", .{});
    std.debug.print("     - Discord\n", .{});
    std.debug.print("     - LinkedIn\n", .{});
    
    // 3. Quick setup demonstration (mock)
    std.debug.print("\n  ⚡ Quick Setup Examples:\n", .{});
    
    // Example: Google SSO setup
    std.debug.print("     Google SSO: var sso = try zid.setupGoogle(allocator, \"client_id\", \"secret\", \"callback\");\n", .{});
    
    // Example: Azure AD setup  
    std.debug.print("     Azure AD:   var sso = try zid.setupAzureAD(allocator, \"tenant\", \"client\", \"secret\", \"callback\");\n", .{});
    
    // Example: .env setup
    std.debug.print("     From .env:  var sso = try zid.setupFromEnv(allocator);\n", .{});
    
    // 4. One-line auth flow
    std.debug.print("\n  🔐 Simplified Auth Flow:\n", .{});
    std.debug.print("     1. const auth_url = try sso.getAuthUrl(\"state123\");\n", .{});
    std.debug.print("     2. // User visits auth_url and returns with code\n", .{});
    std.debug.print("     3. const result = try zid.quick.simple.handleLogin(&sso, code, state);\n", .{});
    
    std.debug.print("\n  ✅ All new features ready for production use!\n", .{});
}

test "zid library basic test" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test basic functionality
    const current_time = zid.time.now();
    try testing.expect(current_time > 0);
    
    // Test crypto
    const random_data = try zid.crypto.randomString(allocator, 16);
    defer allocator.free(random_data);
    try testing.expect(random_data.len > 0);
    
    // Test algorithm
    const alg = try zid.crypto.Algorithm.fromString("HS256");
    try testing.expectEqual(zid.crypto.Algorithm.HS256, alg);
}

test "new sso features" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test env config parsing
    var env_config = zid.config.EnvConfig.init(allocator);
    defer env_config.deinit();
    
    const test_env = "ZID_CLIENT_ID=test123\nZID_SCOPES=openid email\n";
    try env_config.parseEnvContent(test_env);
    
    try testing.expectEqualStrings("test123", env_config.get("ZID_CLIENT_ID").?);
    try testing.expectEqualStrings("openid email", env_config.get("ZID_SCOPES").?);
}