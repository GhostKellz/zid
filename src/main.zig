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