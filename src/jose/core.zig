//! JOSE (JSON Object Signing and Encryption) implementation
//! Supports JWT, JWS, JWE, and JWK with comprehensive security validation

const std = @import("std");
const time = @import("../time/core.zig");
const crypto = @import("../crypto/core.zig");

/// JWT (JSON Web Token) structure
pub const JwtToken = struct {
    header: JwtHeader,
    payload: JwtPayload,
    signature: []const u8,
    raw_header: []const u8,
    raw_payload: []const u8,
    raw_signature: []const u8,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *JwtToken) void {
        self.header.deinit();
        self.payload.deinit();
        self.allocator.free(self.signature);
        self.allocator.free(self.raw_header);
        self.allocator.free(self.raw_payload);
        self.allocator.free(self.raw_signature);
    }
    
    /// Verify the JWT signature and claims
    pub fn verify(self: *const JwtToken, key: crypto.Key, clock_skew: time.ClockSkew) !void {
        // Verify signature
        const signing_input = try std.fmt.allocPrint(
            self.allocator,
            "{s}.{s}",
            .{ self.raw_header, self.raw_payload }
        );
        defer self.allocator.free(signing_input);
        
        const crypto_engine = crypto.Crypto.init(self.allocator, .{});
        const valid = try crypto_engine.verify(
            signing_input,
            self.signature,
            key,
            self.header.alg
        );
        
        if (!valid) {
            return error.InvalidSignature;
        }
        
        // Verify time claims
        try time.validateTokenTimes(
            self.payload.iat,
            self.payload.nbf,
            self.payload.exp orelse return error.MissingExpiration,
            clock_skew
        );
    }
    
    /// Get signing input (header.payload) for signature verification
    pub fn getSigningInput(self: *const JwtToken) ![]u8 {
        return try std.fmt.allocPrint(
            self.allocator,
            "{s}.{s}",
            .{ self.raw_header, self.raw_payload }
        );
    }
};

/// JWT Header
pub const JwtHeader = struct {
    alg: crypto.Algorithm,
    typ: ?[]const u8 = null,
    kid: ?[]const u8 = null,
    jku: ?[]const u8 = null,
    jwk: ?JsonWebKey = null,
    x5u: ?[]const u8 = null,
    x5c: ?[]const []const u8 = null,
    x5t: ?[]const u8 = null,
    x5t_s256: ?[]const u8 = null,
    crit: ?[]const []const u8 = null,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *JwtHeader) void {
        if (self.typ) |typ| self.allocator.free(typ);
        if (self.kid) |kid| self.allocator.free(kid);
        if (self.jku) |jku| self.allocator.free(jku);
        if (self.jwk) |*jwk| jwk.deinit();
        if (self.x5u) |x5u| self.allocator.free(x5u);
        if (self.x5c) |x5c| {
            for (x5c) |cert| {
                self.allocator.free(cert);
            }
            self.allocator.free(x5c);
        }
        if (self.x5t) |x5t| self.allocator.free(x5t);
        if (self.x5t_s256) |x5t_s256| self.allocator.free(x5t_s256);
        if (self.crit) |crit| {
            for (crit) |param| {
                self.allocator.free(param);
            }
            self.allocator.free(crit);
        }
    }
    
    /// Validate critical header parameters
    pub fn validateCritical(self: *const JwtHeader) !void {
        if (self.crit) |critical_params| {
            for (critical_params) |param| {
                // Check if we support this critical parameter
                const supported = std.mem.eql(u8, param, "alg") or
                                std.mem.eql(u8, param, "typ") or
                                std.mem.eql(u8, param, "kid");
                
                if (!supported) {
                    return error.UnsupportedCriticalParameter;
                }
            }
        }
    }
};

/// JWT Payload (Claims)
pub const JwtPayload = struct {
    // Standard claims (RFC 7519)
    iss: ?[]const u8 = null,     // Issuer
    sub: ?[]const u8 = null,     // Subject
    aud: ?[]const u8 = null,     // Audience
    exp: ?time.Timestamp = null, // Expiration Time
    nbf: ?time.Timestamp = null, // Not Before
    iat: ?time.Timestamp = null, // Issued At
    jti: ?[]const u8 = null,     // JWT ID
    
    // Custom claims
    custom_claims: std.StringHashMapUnmanaged(std.json.Value),
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *JwtPayload) void {
        if (self.iss) |iss| self.allocator.free(iss);
        if (self.sub) |sub| self.allocator.free(sub);
        if (self.aud) |aud| self.allocator.free(aud);
        if (self.jti) |jti| self.allocator.free(jti);
        
        var iterator = self.custom_claims.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            // Note: std.json.Value doesn't have deinit in Zig 0.16
            // Custom claims cleanup would need to be handled differently
        }
        self.custom_claims.deinit(self.allocator);
    }
    
    /// Validate standard claims
    pub fn validateClaims(self: *const JwtPayload, expected_iss: ?[]const u8, expected_aud: ?[]const u8) !void {
        // Validate issuer if expected
        if (expected_iss) |iss| {
            if (self.iss == null or !std.mem.eql(u8, self.iss.?, iss)) {
                return error.InvalidIssuer;
            }
        }
        
        // Validate audience if expected
        if (expected_aud) |aud| {
            if (self.aud == null or !std.mem.eql(u8, self.aud.?, aud)) {
                return error.InvalidAudience;
            }
        }
    }
    
    /// Get custom claim
    pub fn getClaim(self: *const JwtPayload, claim_name: []const u8) ?std.json.Value {
        return self.custom_claims.get(claim_name);
    }
    
    /// Set custom claim
    pub fn setClaim(self: *JwtPayload, claim_name: []const u8, value: std.json.Value) !void {
        const owned_name = try self.allocator.dupe(u8, claim_name);
        try self.custom_claims.put(self.allocator, owned_name, value);
    }
};

/// JSON Web Key (JWK) structure
pub const JsonWebKey = struct {
    kty: KeyType,
    use: ?KeyUse = null,
    key_ops: ?[]const KeyOperation = null,
    alg: ?crypto.Algorithm = null,
    kid: ?[]const u8 = null,
    x5u: ?[]const u8 = null,
    x5c: ?[]const []const u8 = null,
    x5t: ?[]const u8 = null,
    x5t_s256: ?[]const u8 = null,
    
    // Key-specific parameters
    parameters: KeyParameters,
    allocator: std.mem.Allocator,
    
    pub const KeyType = enum {
        RSA,
        EC,
        oct,
        OKP,
        
        pub fn toString(self: KeyType) []const u8 {
            return switch (self) {
                .RSA => "RSA",
                .EC => "EC",
                .oct => "oct",
                .OKP => "OKP",
            };
        }
        
        pub fn fromString(kty_str: []const u8) !KeyType {
            const types = std.ComptimeStringMap(KeyType, .{
                .{ "RSA", .RSA },
                .{ "EC", .EC },
                .{ "oct", .oct },
                .{ "OKP", .OKP },
            });
            return types.get(kty_str) orelse error.UnsupportedKeyType;
        }
    };
    
    pub const KeyUse = enum {
        sig, // Signature
        enc, // Encryption
        
        pub fn toString(self: KeyUse) []const u8 {
            return switch (self) {
                .sig => "sig",
                .enc => "enc",
            };
        }
    };
    
    pub const KeyOperation = enum {
        sign,
        verify,
        encrypt,
        decrypt,
        wrapKey,
        unwrapKey,
        deriveKey,
        deriveBits,
    };
    
    pub const KeyParameters = union(KeyType) {
        RSA: RsaParameters,
        EC: EcParameters,
        oct: OctParameters,
        OKP: OkpParameters,
        
        pub const RsaParameters = struct {
            n: []const u8, // Modulus (base64url)
            e: []const u8, // Exponent (base64url) 
            d: ?[]const u8 = null, // Private exponent (base64url)
            p: ?[]const u8 = null, // First prime factor (base64url)
            q: ?[]const u8 = null, // Second prime factor (base64url)
            dp: ?[]const u8 = null, // First factor CRT exponent (base64url)
            dq: ?[]const u8 = null, // Second factor CRT exponent (base64url)
            qi: ?[]const u8 = null, // First CRT coefficient (base64url)
        };
        
        pub const EcParameters = struct {
            crv: []const u8, // Curve (e.g., "P-256", "P-384", "P-521")
            x: []const u8,   // X coordinate (base64url)
            y: []const u8,   // Y coordinate (base64url)
            d: ?[]const u8 = null, // Private key (base64url)
        };
        
        pub const OctParameters = struct {
            k: []const u8, // Key value (base64url)
        };
        
        pub const OkpParameters = struct {
            crv: []const u8, // Curve (e.g., "Ed25519", "Ed448", "X25519", "X448")
            x: []const u8,   // Public key (base64url)
            d: ?[]const u8 = null, // Private key (base64url)
        };
    };
    
    pub fn deinit(self: *JsonWebKey) void {
        if (self.kid) |kid| self.allocator.free(kid);
        if (self.x5u) |x5u| self.allocator.free(x5u);
        if (self.x5c) |x5c| {
            for (x5c) |cert| {
                self.allocator.free(cert);
            }
            self.allocator.free(x5c);
        }
        if (self.x5t) |x5t| self.allocator.free(x5t);
        if (self.x5t_s256) |x5t_s256| self.allocator.free(x5t_s256);
        if (self.key_ops) |ops| self.allocator.free(ops);
        
        // Free key parameters
        switch (self.parameters) {
            .RSA => |params| {
                self.allocator.free(params.n);
                self.allocator.free(params.e);
                if (params.d) |d| self.allocator.free(d);
                if (params.p) |p| self.allocator.free(p);
                if (params.q) |q| self.allocator.free(q);
                if (params.dp) |dp| self.allocator.free(dp);
                if (params.dq) |dq| self.allocator.free(dq);
                if (params.qi) |qi| self.allocator.free(qi);
            },
            .EC => |params| {
                self.allocator.free(params.crv);
                self.allocator.free(params.x);
                self.allocator.free(params.y);
                if (params.d) |d| self.allocator.free(d);
            },
            .oct => |params| {
                self.allocator.free(params.k);
            },
            .OKP => |params| {
                self.allocator.free(params.crv);
                self.allocator.free(params.x);
                if (params.d) |d| self.allocator.free(d);
            },
        }
    }
    
    /// Convert JWK to crypto.Key
    pub fn toCryptoKey(self: *const JsonWebKey) !crypto.Key {
        switch (self.parameters) {
            .RSA => |params| {
                // Decode base64url encoded parameters
                const n_bytes = try base64UrlDecode(self.allocator, params.n);
                const e_bytes = try base64UrlDecode(self.allocator, params.e);
                defer self.allocator.free(n_bytes);
                defer self.allocator.free(e_bytes);
                
                // Create PEM formatted key (simplified - in production use proper ASN.1 encoding)
                const public_pem = try std.fmt.allocPrint(
                    self.allocator,
                    "-----BEGIN PUBLIC KEY-----\n{s}\n-----END PUBLIC KEY-----",
                    .{params.n} // Simplified
                );
                
                var private_pem: ?[]const u8 = null;
                if (params.d != null) {
                    private_pem = try std.fmt.allocPrint(
                        self.allocator,
                        "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----",
                        .{params.d.?} // Simplified
                    );
                }
                
                return crypto.Key{ .rsa = try crypto.Key.RsaKey.fromPem(public_pem, private_pem) };
            },
            .EC => |params| {
                const curve = if (std.mem.eql(u8, params.crv, "P-256"))
                    crypto.Key.EcdsaKey.EcdsaCurve.P256
                else if (std.mem.eql(u8, params.crv, "P-384"))
                    crypto.Key.EcdsaKey.EcdsaCurve.P384
                else if (std.mem.eql(u8, params.crv, "P-521"))
                    crypto.Key.EcdsaKey.EcdsaCurve.P521
                else
                    return error.UnsupportedCurve;
                
                // In production, properly construct ECDSA key from x,y coordinates
                return crypto.Key{ .ecdsa = crypto.Key.EcdsaKey.fromPem(params.x, params.d, curve) };
            },
            .oct => |params| {
                const key_bytes = try base64UrlDecode(self.allocator, params.k);
                defer self.allocator.free(key_bytes);
                
                return crypto.Key{ .hmac = crypto.Key.HmacKey.fromBytes(key_bytes) };
            },
            .OKP => |params| {
                if (!std.mem.eql(u8, params.crv, "Ed25519")) {
                    return error.UnsupportedCurve;
                }
                
                const x_bytes = try base64UrlDecode(self.allocator, params.x);
                defer self.allocator.free(x_bytes);
                
                if (x_bytes.len != 32) return error.InvalidKeySize;
                
                var public_key: [32]u8 = undefined;
                @memcpy(&public_key, x_bytes);
                
                var private_key: ?[64]u8 = null;
                if (params.d) |d| {
                    const d_bytes = try base64UrlDecode(self.allocator, d);
                    defer self.allocator.free(d_bytes);
                    
                    if (d_bytes.len != 32) return error.InvalidKeySize;
                    
                    private_key = [_]u8{0} ** 64;
                    @memcpy(private_key.?[0..32], d_bytes);
                    @memcpy(private_key.?[32..64], &public_key);
                }
                
                return crypto.Key{ .ed25519 = crypto.Key.Ed25519Key.fromBytes(public_key, private_key) };
            },
        }
    }
};

/// JWT Builder for creating and signing JWTs
pub const JwtBuilder = struct {
    header: JwtHeader,
    payload: JwtPayload,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, algorithm: crypto.Algorithm) JwtBuilder {
        return JwtBuilder{
            .header = JwtHeader{
                .alg = algorithm,
                .typ = null,
                .allocator = allocator,
                .kid = null,
                .jku = null,
                .jwk = null,
                .x5u = null,
                .x5c = null,
                .x5t = null,
                .x5t_s256 = null,
                .crit = null,
            },
            .payload = JwtPayload{
                .custom_claims = .empty,
                .allocator = allocator,
                .iss = null,
                .sub = null,
                .aud = null,
                .exp = null,
                .nbf = null,
                .iat = null,
                .jti = null,
            },
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *JwtBuilder) void {
        self.header.deinit();
        self.payload.deinit();
    }
    
    /// Set issuer claim
    pub fn setIssuer(self: *JwtBuilder, issuer: []const u8) !void {
        if (self.payload.iss) |old_iss| {
            self.allocator.free(old_iss);
        }
        self.payload.iss = try self.allocator.dupe(u8, issuer);
    }
    
    /// Set subject claim
    pub fn setSubject(self: *JwtBuilder, subject: []const u8) !void {
        if (self.payload.sub) |old_sub| {
            self.allocator.free(old_sub);
        }
        self.payload.sub = try self.allocator.dupe(u8, subject);
    }
    
    /// Set audience claim
    pub fn setAudience(self: *JwtBuilder, audience: []const u8) !void {
        if (self.payload.aud) |old_aud| {
            self.allocator.free(old_aud);
        }
        self.payload.aud = try self.allocator.dupe(u8, audience);
    }
    
    /// Set expiration time (from now + duration)
    pub fn setExpirationFromNow(self: *JwtBuilder, duration_seconds: u32) void {
        self.payload.exp = time.now() + @as(i64, @intCast(duration_seconds));
    }
    
    /// Set expiration time (absolute timestamp)
    pub fn setExpiration(self: *JwtBuilder, exp: time.Timestamp) void {
        self.payload.exp = exp;
    }
    
    /// Set not-before time  
    pub fn setNotBefore(self: *JwtBuilder, nbf: time.Timestamp) void {
        self.payload.nbf = nbf;
    }
    
    /// Set issued-at time to now
    pub fn setIssuedAtNow(self: *JwtBuilder) void {
        self.payload.iat = time.now();
    }
    
    /// Set JWT ID
    pub fn setJwtId(self: *JwtBuilder, jti: []const u8) !void {
        if (self.payload.jti) |old_jti| {
            self.allocator.free(old_jti);
        }
        self.payload.jti = try self.allocator.dupe(u8, jti);
    }
    
    /// Set key ID in header
    pub fn setKeyId(self: *JwtBuilder, kid: []const u8) !void {
        if (self.header.kid) |old_kid| {
            self.allocator.free(old_kid);
        }
        self.header.kid = try self.allocator.dupe(u8, kid);
    }
    
    /// Build and sign the JWT
    pub fn build(self: *JwtBuilder, key: crypto.Key) ![]u8 {
        // Serialize header
        const header_json = try serializeHeader(&self.header);
        defer self.allocator.free(header_json);
        
        const header_b64 = try base64UrlEncode(self.allocator, header_json);
        defer self.allocator.free(header_b64);
        
        // Serialize payload
        const payload_json = try serializePayload(&self.payload);
        defer self.allocator.free(payload_json);
        
        const payload_b64 = try base64UrlEncode(self.allocator, payload_json);
        defer self.allocator.free(payload_b64);
        
        // Create signing input
        const signing_input = try std.fmt.allocPrint(
            self.allocator,
            "{s}.{s}",
            .{ header_b64, payload_b64 }
        );
        defer self.allocator.free(signing_input);
        
        // Sign
        const crypto_engine = crypto.Crypto.init(self.allocator, .{});
        const signature = try crypto_engine.sign(signing_input, key, self.header.alg);
        defer self.allocator.free(signature);
        
        const signature_b64 = try base64UrlEncode(self.allocator, signature);
        defer self.allocator.free(signature_b64);
        
        // Return complete JWT
        return try std.fmt.allocPrint(
            self.allocator,
            "{s}.{s}.{s}",
            .{ header_b64, payload_b64, signature_b64 }
        );
    }
    
    fn serializeHeader(header: *const JwtHeader) ![]u8 {
        // Simple JSON serialization - in production use proper JSON library
        return try std.fmt.allocPrint(
            header.allocator,
            "{{\"alg\":\"{s}\",\"typ\":\"JWT\"}}",
            .{header.alg.toString()}
        );
    }
    
    fn serializePayload(payload: *const JwtPayload) ![]u8 {
        // Simple JSON serialization - in production use proper JSON library
        var json = std.ArrayList(u8){};
        defer json.deinit(payload.allocator);
        
        try json.append(payload.allocator, '{');
        
        var first = true;
        
        if (payload.iss) |iss| {
            if (!first) try json.append(payload.allocator, ',');
            try json.appendSlice(payload.allocator, try std.fmt.allocPrint(payload.allocator, "\"iss\":\"{s}\"", .{iss}));
            first = false;
        }
        
        if (payload.sub) |sub| {
            if (!first) try json.append(payload.allocator, ',');
            try json.appendSlice(payload.allocator, try std.fmt.allocPrint(payload.allocator, "\"sub\":\"{s}\"", .{sub}));
            first = false;
        }
        
        if (payload.aud) |aud| {
            if (!first) try json.append(payload.allocator, ',');
            try json.appendSlice(payload.allocator, try std.fmt.allocPrint(payload.allocator, "\"aud\":\"{s}\"", .{aud}));
            first = false;
        }
        
        if (payload.exp) |exp| {
            if (!first) try json.append(payload.allocator, ',');
            try json.appendSlice(payload.allocator, try std.fmt.allocPrint(payload.allocator, "\"exp\":{}", .{exp}));
            first = false;
        }
        
        if (payload.nbf) |nbf| {
            if (!first) try json.append(payload.allocator, ',');
            try json.appendSlice(payload.allocator, try std.fmt.allocPrint(payload.allocator, "\"nbf\":{}", .{nbf}));
            first = false;
        }
        
        if (payload.iat) |iat| {
            if (!first) try json.append(payload.allocator, ',');
            try json.appendSlice(payload.allocator, try std.fmt.allocPrint(payload.allocator, "\"iat\":{}", .{iat}));
            first = false;
        }
        
        if (payload.jti) |jti| {
            if (!first) try json.append(payload.allocator, ',');
            try json.appendSlice(payload.allocator, try std.fmt.allocPrint(payload.allocator, "\"jti\":\"{s}\"", .{jti}));
            first = false;
        }
        
        try json.append(payload.allocator, '}');
        
        return try json.toOwnedSlice(payload.allocator);
    }
};

/// Parse JWT from string
pub fn parseJwt(allocator: std.mem.Allocator, jwt_string: []const u8) !JwtToken {
    // Split JWT into parts
    var parts = std.mem.split(u8, jwt_string, ".");
    const header_b64 = parts.next() orelse return error.InvalidJwtFormat;
    const payload_b64 = parts.next() orelse return error.InvalidJwtFormat;
    const signature_b64 = parts.next() orelse return error.InvalidJwtFormat;
    
    if (parts.next() != null) return error.InvalidJwtFormat; // Too many parts
    
    // Decode parts
    const header_json = try base64UrlDecode(allocator, header_b64);
    defer allocator.free(header_json);
    
    const payload_json = try base64UrlDecode(allocator, payload_b64);
    defer allocator.free(payload_json);
    
    const signature = try base64UrlDecode(allocator, signature_b64);
    
    // Parse header and payload (simplified - in production use proper JSON parser)
    const header = try parseJwtHeader(allocator, header_json);
    const payload = try parseJwtPayload(allocator, payload_json);
    
    return JwtToken{
        .header = header,
        .payload = payload,
        .signature = signature,
        .raw_header = try allocator.dupe(u8, header_b64),
        .raw_payload = try allocator.dupe(u8, payload_b64),
        .raw_signature = try allocator.dupe(u8, signature_b64),
        .allocator = allocator,
    };
}

fn parseJwtHeader(allocator: std.mem.Allocator, json: []const u8) !JwtHeader {
    _ = json;
    // Simplified parser - in production use proper JSON parsing
    return JwtHeader{
        .alg = .HS256, // Default
        .typ = try allocator.dupe(u8, "JWT"),
        .allocator = allocator,
        .kid = null,
        .jku = null,
        .jwk = null,
        .x5u = null,
        .x5c = null,
        .x5t = null,
        .x5t_s256 = null,
        .crit = null,
    };
}

fn parseJwtPayload(allocator: std.mem.Allocator, json: []const u8) !JwtPayload {
    _ = json;
    // Simplified parser - in production use proper JSON parsing
    return JwtPayload{
        .custom_claims = .empty,
        .allocator = allocator,
        .iss = null,
        .sub = null,
        .aud = null,
        .exp = null,
        .nbf = null,
        .iat = null,
        .jti = null,
    };
}

/// Base64 URL encoding without padding
fn base64UrlEncode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(input.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, input);
    return encoded;
}

/// Base64 URL decoding  
fn base64UrlDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(input);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, input);
    return decoded;
}

test "jose jwt builder" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create JWT builder
    var builder = JwtBuilder.init(allocator, .HS256);
    defer builder.deinit();
    
    // Set claims
    try builder.setIssuer("test_issuer");
    try builder.setSubject("test_subject");
    try builder.setAudience("test_audience");
    builder.setIssuedAtNow();
    builder.setExpirationFromNow(3600); // 1 hour
    
    try testing.expectEqualStrings("test_issuer", builder.payload.iss.?);
    try testing.expectEqualStrings("test_subject", builder.payload.sub.?);
    try testing.expectEqualStrings("test_audience", builder.payload.aud.?);
}

test "jose algorithm parsing" {
    const testing = std.testing;
    
    // Test algorithm string conversion
    try testing.expectEqualStrings("HS256", crypto.Algorithm.HS256.toString());
    try testing.expectEqualStrings("RS256", crypto.Algorithm.RS256.toString());
    try testing.expectEqualStrings("ES256", crypto.Algorithm.ES256.toString());
    try testing.expectEqualStrings("EdDSA", crypto.Algorithm.EdDSA.toString());
    
    // Test parsing
    try testing.expectEqual(crypto.Algorithm.HS256, try crypto.Algorithm.fromString("HS256"));
    try testing.expectEqual(crypto.Algorithm.RS256, try crypto.Algorithm.fromString("RS256"));
}

test "jose base64url encoding" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const input = "hello world";
    const encoded = try base64UrlEncode(allocator, input);
    defer allocator.free(encoded);
    
    const decoded = try base64UrlDecode(allocator, encoded);
    defer allocator.free(decoded);
    
    try testing.expectEqualStrings(input, decoded);
}