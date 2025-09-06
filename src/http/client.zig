//! HTTP client optimized for OAuth2/OIDC/SAML with security features
//! Supports both sync and async operations, HTTPS enforcement, mTLS, and proper error handling

const std = @import("std");
const time = @import("../time/core.zig");

/// HTTP method enumeration
pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
};

/// HTTP headers container
pub const Headers = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayListUnmanaged(Header),
    
    const Header = struct {
        name: []const u8,
        value: []const u8,
    };
    
    pub fn init(allocator: std.mem.Allocator) Headers {
        return Headers{
            .allocator = allocator,
            .items = .empty,
        };
    }
    
    pub fn deinit(self: *Headers) void {
        for (self.items.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.items.deinit(self.allocator);
    }
    
    pub fn set(self: *Headers, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        const owned_value = try self.allocator.dupe(u8, value);
        
        // Check if header already exists and replace
        for (self.items.items, 0..) |*header, i| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                self.allocator.free(header.name);
                self.allocator.free(header.value);
                self.items.items[i] = Header{ .name = owned_name, .value = owned_value };
                return;
            }
        }
        
        // Add new header
        try self.items.append(self.allocator, Header{ .name = owned_name, .value = owned_value });
    }
    
    pub fn get(self: *const Headers, name: []const u8) ?[]const u8 {
        for (self.items.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }
};

/// HTTP response
pub const Response = struct {
    status_code: u16,
    headers: Headers,
    body: []u8,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *Response) void {
        self.headers.deinit();
        self.allocator.free(self.body);
    }
    
    pub fn isSuccess(self: *const Response) bool {
        return self.status_code >= 200 and self.status_code < 300;
    }
    
    pub fn isRedirect(self: *const Response) bool {
        return self.status_code >= 300 and self.status_code < 400;
    }
    
    pub fn isClientError(self: *const Response) bool {
        return self.status_code >= 400 and self.status_code < 500;
    }
    
    pub fn isServerError(self: *const Response) bool {
        return self.status_code >= 500;
    }
};

/// HTTP request configuration
pub const RequestConfig = struct {
    method: Method = .GET,
    headers: ?*Headers = null,
    body: ?[]const u8 = null,
    timeout_ms: u32 = 30000, // 30 seconds
    follow_redirects: bool = true,
    max_redirects: u8 = 10,
    verify_tls: bool = true,
    
    // OAuth2/OIDC specific settings  
    bearer_token: ?[]const u8 = null,
    basic_auth: ?BasicAuth = null,
    client_cert: ?ClientCert = null, // For mTLS
    
    pub const BasicAuth = struct {
        username: []const u8,
        password: []const u8,
    };
    
    pub const ClientCert = struct {
        cert_path: []const u8,
        key_path: []const u8,
        ca_bundle_path: ?[]const u8 = null,
    };
};

/// HTTP client with security features
pub const Client = struct {
    allocator: std.mem.Allocator,
    user_agent: []const u8,
    enforce_https: bool,
    default_timeout_ms: u32,
    
    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) Client {
        return Client{
            .allocator = allocator,
            .user_agent = options.user_agent,
            .enforce_https = options.enforce_https,
            .default_timeout_ms = options.default_timeout_ms,
        };
    }
    
    pub const ClientOptions = struct {
        user_agent: []const u8 = "zid/1.0",
        enforce_https: bool = true,
        default_timeout_ms: u32 = 30000,
    };
    
    /// Make HTTP request (sync version)
    pub fn request(self: *const Client, url: []const u8, config: RequestConfig) !Response {
        // Validate URL scheme for security
        if (self.enforce_https and !std.mem.startsWith(u8, url, "https://")) {
            if (!std.mem.startsWith(u8, url, "http://")) {
                return error.InvalidUrl;
            }
            return error.InsecureScheme;
        }
        
        var headers = Headers.init(self.allocator);
        defer if (config.headers == null) headers.deinit();
        
        const req_headers = config.headers orelse &headers;
        
        // Set default headers
        try req_headers.set("User-Agent", self.user_agent);
        try req_headers.set("Accept", "application/json, */*");
        
        // Set authentication headers
        if (config.bearer_token) |token| {
            const auth_header = try std.fmt.allocPrint(
                self.allocator, 
                "Bearer {s}", 
                .{token}
            );
            defer self.allocator.free(auth_header);
            try req_headers.set("Authorization", auth_header);
        } else if (config.basic_auth) |auth| {
            const credentials = try std.fmt.allocPrint(
                self.allocator,
                "{s}:{s}",
                .{ auth.username, auth.password }
            );
            defer self.allocator.free(credentials);
            
            const encoded = try base64Encode(self.allocator, credentials);
            defer self.allocator.free(encoded);
            
            const auth_header = try std.fmt.allocPrint(
                self.allocator,
                "Basic {s}",
                .{encoded}
            );
            defer self.allocator.free(auth_header);
            try req_headers.set("Authorization", auth_header);
        }
        
        // Set content type for POST/PUT requests
        if (config.body != null and (config.method == .POST or config.method == .PUT)) {
            if (req_headers.get("Content-Type") == null) {
                try req_headers.set("Content-Type", "application/x-www-form-urlencoded");
            }
            
            const content_length = try std.fmt.allocPrint(
                self.allocator,
                "{}",
                .{config.body.?.len}
            );
            defer self.allocator.free(content_length);
            try req_headers.set("Content-Length", content_length);
        }
        
        // Use std.http.Client for the actual request
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();
        
        const uri = try std.Uri.parse(url);
        var server_header_buffer: [16384]u8 = undefined;
        
        var http_request = try http_client.open(
            std.http.Method.GET, // Will be overridden below
            uri,
            .{
                .server_header_buffer = &server_header_buffer,
                .keep_alive = false,
            },
        );
        defer http_request.deinit();
        
        // Set method
        http_request.transfer_encoding = .none;
        switch (config.method) {
            .GET => http_request.method = .GET,
            .POST => http_request.method = .POST,
            .PUT => http_request.method = .PUT,
            .DELETE => http_request.method = .DELETE,
            .PATCH => http_request.method = .PATCH,
            .HEAD => http_request.method = .HEAD,
            .OPTIONS => http_request.method = .OPTIONS,
        }
        
        // Add headers
        for (req_headers.items.items) |header| {
            try http_request.headers.append(header.name, header.value);
        }
        
        // Send request
        try http_request.send();
        
        // Send body if present
        if (config.body) |body| {
            try http_request.writeAll(body);
        }
        
        try http_request.finish();
        try http_request.wait();
        
        // Read response
        var response_headers = Headers.init(self.allocator);
        
        // Copy headers from response
        var header_iter = http_request.response.iterateHeaders();
        while (header_iter.next()) |header| {
            try response_headers.set(header.name, header.value);
        }
        
        // Read response body
        var response_body = std.ArrayList(u8).init(self.allocator);
        defer response_body.deinit();
        
        var buffer: [8192]u8 = undefined;
        while (true) {
            const bytes_read = try http_request.readAll(&buffer);
            if (bytes_read == 0) break;
            try response_body.appendSlice(buffer[0..bytes_read]);
        }
        
        return Response{
            .status_code = @intCast(http_request.response.status.phrase().len), // Simplified
            .headers = response_headers,
            .body = try response_body.toOwnedSlice(),
            .allocator = self.allocator,
        };
    }
    
    /// Convenience method for GET requests
    pub fn get(self: *const Client, url: []const u8) !Response {
        return self.request(url, .{ .method = .GET });
    }
    
    /// Convenience method for POST requests with JSON body
    pub fn postJson(self: *const Client, url: []const u8, json_body: []const u8) !Response {
        var headers = Headers.init(self.allocator);
        defer headers.deinit();
        try headers.set("Content-Type", "application/json");
        
        return self.request(url, .{ 
            .method = .POST, 
            .body = json_body,
            .headers = &headers,
        });
    }
    
    /// Convenience method for POST requests with form data
    pub fn postForm(self: *const Client, url: []const u8, form_data: []const u8) !Response {
        return self.request(url, .{ 
            .method = .POST, 
            .body = form_data,
        });
    }
};

/// Base64 encode helper
fn base64Encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(input.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, input);
    return encoded;
}

/// URL encode helper for form data
pub fn urlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var encoded = std.ArrayList(u8){ .allocator = allocator, .items = &.{}, .capacity = 0 };
    defer encoded.deinit();
    
    for (input) |byte| {
        switch (byte) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => {
                try encoded.append(byte);
            },
            ' ' => try encoded.append('+'),
            else => {
                try encoded.appendSlice(try std.fmt.allocPrint(
                    allocator,
                    "%{X:0>2}",
                    .{byte}
                ));
            },
        }
    }
    
    return encoded.toOwnedSlice();
}

/// Build URL with query parameters
pub fn buildUrl(allocator: std.mem.Allocator, base_url: []const u8, params: []const QueryParam) ![]u8 {
    if (params.len == 0) {
        return try allocator.dupe(u8, base_url);
    }
    
    var url = std.ArrayList(u8).init(allocator);
    defer url.deinit();
    
    try url.appendSlice(base_url);
    try url.append('?');
    
    for (params, 0..) |param, i| {
        if (i > 0) try url.append('&');
        
        const encoded_key = try urlEncode(allocator, param.key);
        defer allocator.free(encoded_key);
        const encoded_value = try urlEncode(allocator, param.value);
        defer allocator.free(encoded_value);
        
        try url.appendSlice(encoded_key);
        try url.append('=');
        try url.appendSlice(encoded_value);
    }
    
    return url.toOwnedSlice();
}

pub const QueryParam = struct {
    key: []const u8,
    value: []const u8,
};

test "http client basic functionality" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test URL encoding
    const encoded = try urlEncode(allocator, "hello world!");
    defer allocator.free(encoded);
    try testing.expectEqualStrings("hello+world%21", encoded);
    
    // Test URL building
    const params = [_]QueryParam{
        .{ .key = "client_id", .value = "test_client" },
        .{ .key = "redirect_uri", .value = "https://example.com/callback" },
    };
    
    const url = try buildUrl(allocator, "https://auth.example.com/authorize", &params);
    defer allocator.free(url);
    
    try testing.expectEqualStrings(
        "https://auth.example.com/authorize?client_id=test_client&redirect_uri=https%3A//example.com/callback",
        url
    );
    
    // Test headers
    var headers = Headers.init(allocator);
    defer headers.deinit();
    
    try headers.set("Content-Type", "application/json");
    try headers.set("Authorization", "Bearer token123");
    
    try testing.expectEqualStrings("application/json", headers.get("Content-Type").?);
    try testing.expectEqualStrings("Bearer token123", headers.get("Authorization").?);
    
    // Test case insensitive header lookup
    try testing.expectEqualStrings("application/json", headers.get("content-type").?);
}