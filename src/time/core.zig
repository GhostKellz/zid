//! Time utilities for OIDC/OAuth2/SAML with clock skew tolerance
//! Provides both monotonic and wall clock helpers with proper leeway handling

const std = @import("std");

/// Unix timestamp in seconds
pub const Timestamp = i64;

/// Duration in seconds  
pub const Duration = u32;

/// Clock skew tolerance configuration
pub const ClockSkew = struct {
    /// Maximum allowed clock skew in seconds (default: 300 = 5 minutes)
    max_skew_seconds: Duration = 300,
    /// Whether to be strict about time validation
    strict_validation: bool = true,
};

/// Get current Unix timestamp in seconds
pub fn now() Timestamp {
    return @intCast(@divTrunc(std.time.milliTimestamp(), 1000));
}

/// Get current Unix timestamp in milliseconds  
pub fn nowMillis() i64 {
    return std.time.milliTimestamp();
}

/// Get monotonic timestamp for internal timing (nanoseconds)
pub fn monotonic() u64 {
    return std.time.nanoTimestamp();
}

/// Check if a timestamp is valid within clock skew tolerance
pub fn isValidTimestamp(timestamp: Timestamp, clock_skew: ClockSkew) bool {
    const current = now();
    const diff = if (timestamp > current) timestamp - current else current - timestamp;
    return diff <= clock_skew.max_skew_seconds;
}

/// Validate token expiration with clock skew
pub fn isTokenExpired(exp: Timestamp, clock_skew: ClockSkew) bool {
    const current = now();
    const effective_exp = exp + @as(i64, @intCast(clock_skew.max_skew_seconds));
    return current >= effective_exp;
}

/// Validate token not-before time with clock skew  
pub fn isTokenValidYet(nbf: Timestamp, clock_skew: ClockSkew) bool {
    const current = now();
    const effective_nbf = nbf - @as(i64, @intCast(clock_skew.max_skew_seconds));
    return current >= effective_nbf;
}

/// Validate issued-at time is not too far in the future
pub fn isIssuedAtValid(iat: Timestamp, clock_skew: ClockSkew) bool {
    const current = now();
    const max_future = current + @as(i64, @intCast(clock_skew.max_skew_seconds));
    return iat <= max_future;
}

/// Comprehensive token time validation
pub fn validateTokenTimes(iat: ?Timestamp, nbf: ?Timestamp, exp: Timestamp, clock_skew: ClockSkew) !void {
    // Always validate expiration
    if (isTokenExpired(exp, clock_skew)) {
        return error.TokenExpired;
    }
    
    // Validate issued-at if present
    if (iat) |issued_at| {
        if (!isIssuedAtValid(issued_at, clock_skew)) {
            return error.InvalidIssuedAt;
        }
    }
    
    // Validate not-before if present
    if (nbf) |not_before| {
        if (!isTokenValidYet(not_before, clock_skew)) {
            return error.TokenNotValidYet;
        }
    }
    
    // Additional validation: nbf should not be after exp
    if (nbf != null and iat != null) {
        if (nbf.? > exp) {
            return error.InvalidTokenTimes;
        }
    }
}

/// Format timestamp as ISO 8601 string (UTC)
pub fn formatIso8601(timestamp: Timestamp, allocator: std.mem.Allocator) ![]u8 {
    const epoch_secs: u64 = @intCast(timestamp);
    const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
    const day_seconds = epoch.getDaySeconds();
    const epoch_day = epoch.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    
    return std.fmt.allocPrint(allocator, 
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        .{
            year_day.year, 
            month_day.month.numeric(), 
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(), 
            day_seconds.getSecondsIntoMinute()
        }
    );
}

/// Parse ISO 8601 timestamp string to Unix timestamp
pub fn parseIso8601(iso_string: []const u8) !Timestamp {
    // Simple ISO 8601 parser for "YYYY-MM-DDTHH:MM:SSZ" format
    if (iso_string.len != 20 or iso_string[19] != 'Z' or iso_string[10] != 'T') {
        return error.InvalidIso8601Format;
    }
    
    const year = try std.fmt.parseInt(u16, iso_string[0..4], 10);
    const month = try std.fmt.parseInt(u8, iso_string[5..7], 10);
    const day = try std.fmt.parseInt(u8, iso_string[8..10], 10);
    const hour = try std.fmt.parseInt(u8, iso_string[11..13], 10);
    const minute = try std.fmt.parseInt(u8, iso_string[14..16], 10);
    const second = try std.fmt.parseInt(u8, iso_string[17..19], 10);
    
    // Basic validation
    if (month < 1 or month > 12) return error.InvalidMonth;
    if (day < 1 or day > 31) return error.InvalidDay;
    if (hour > 23) return error.InvalidHour;
    if (minute > 59) return error.InvalidMinute;
    if (second > 59) return error.InvalidSecond;
    
    // Convert to Unix timestamp (simplified calculation)
    // This is a basic implementation - in production you'd want more robust date handling
    const days_since_epoch = daysSinceEpoch(year, month, day);
    const seconds_in_day = hour * 3600 + minute * 60 + second;
    return @intCast(days_since_epoch * 86400 + seconds_in_day);
}

/// Calculate days since Unix epoch (1970-01-01)
fn daysSinceEpoch(year: u16, month: u8, day: u8) i32 {
    // Simplified calculation - in production use std.time functions
    var y: i32 = @intCast(year);
    var m: i32 = @intCast(month);
    const d: i32 = @intCast(day);
    
    if (m <= 2) {
        y -= 1;
        m += 12;
    }
    
    const a = @divTrunc(y, 100);
    const b = @divTrunc(a, 4);
    const c = 2 - a + b;
    const e = @as(i32, @intFromFloat(@floor(365.25 * @as(f64, @floatFromInt(y + 4716)))));
    const f = @as(i32, @intFromFloat(@floor(30.6001 * @as(f64, @floatFromInt(m + 1)))));
    
    return c + d + e + f - 1524 - 719163; // 719163 is days from year 1 to 1970
}

test "time utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test basic timestamp functions
    const current = now();
    try testing.expect(current > 0);
    
    const millis = nowMillis();
    try testing.expect(millis > current * 1000);
    
    const mono = monotonic();
    try testing.expect(mono > 0);
    
    // Test clock skew validation
    const clock_skew = ClockSkew{ .max_skew_seconds = 300 };
    
    // Current time should be valid
    try testing.expect(isValidTimestamp(current, clock_skew));
    
    // Time within skew should be valid
    try testing.expect(isValidTimestamp(current + 100, clock_skew));
    try testing.expect(isValidTimestamp(current - 100, clock_skew));
    
    // Time outside skew should be invalid
    try testing.expect(!isValidTimestamp(current + 400, clock_skew));
    try testing.expect(!isValidTimestamp(current - 400, clock_skew));
    
    // Test token time validation
    const future_exp = current + 3600; // 1 hour from now
    const past_exp = current - 3600;   // 1 hour ago
    
    try testing.expect(!isTokenExpired(future_exp, clock_skew));
    try testing.expect(isTokenExpired(past_exp, clock_skew));
    
    // Test comprehensive validation
    try validateTokenTimes(current - 60, current, future_exp, clock_skew);
    
    // Should fail with expired token
    try testing.expectError(error.TokenExpired, 
        validateTokenTimes(current - 60, current, past_exp, clock_skew));
    
    // Test ISO 8601 formatting
    const iso = try formatIso8601(1640995200, allocator); // 2022-01-01T00:00:00Z
    defer allocator.free(iso);
    try testing.expectEqualStrings("2022-01-01T00:00:00Z", iso);
    
    // Test ISO 8601 parsing
    const parsed = try parseIso8601("2022-01-01T00:00:00Z");
    try testing.expect(parsed == 1640995200);
}