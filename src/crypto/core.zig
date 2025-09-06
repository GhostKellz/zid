//! Cryptographic primitives for OIDC/OAuth2/SAML with security-first design
//! Implements algorithm whitelisting, constant-time operations, and secure defaults

const std = @import("std");
const time = @import("../time/core.zig");

/// Supported cryptographic algorithms (whitelisted)
pub const Algorithm = enum {
    // HMAC algorithms
    HS256, // HMAC with SHA-256
    HS384, // HMAC with SHA-384
    HS512, // HMAC with SHA-512
    
    // RSA algorithms
    RS256, // RSASSA-PKCS1-v1_5 with SHA-256
    RS384, // RSASSA-PKCS1-v1_5 with SHA-384
    RS512, // RSASSA-PKCS1-v1_5 with SHA-512
    PS256, // RSASSA-PSS with SHA-256
    PS384, // RSASSA-PSS with SHA-384
    PS512, // RSASSA-PSS with SHA-512
    
    // ECDSA algorithms
    ES256, // ECDSA with P-256 and SHA-256
    ES384, // ECDSA with P-384 and SHA-384
    ES512, // ECDSA with P-521 and SHA-512
    
    // EdDSA algorithms
    EdDSA, // EdDSA with Ed25519
    
    pub fn toString(self: Algorithm) []const u8 {
        return switch (self) {
            .HS256 => "HS256",
            .HS384 => "HS384", 
            .HS512 => "HS512",
            .RS256 => "RS256",
            .RS384 => "RS384",
            .RS512 => "RS512",
            .PS256 => "PS256",
            .PS384 => "PS384",
            .PS512 => "PS512",
            .ES256 => "ES256",
            .ES384 => "ES384",
            .ES512 => "ES512",
            .EdDSA => "EdDSA",
        };
    }
    
    pub fn fromString(alg_str: []const u8) !Algorithm {
        const algorithms = std.StaticStringMap(Algorithm).initComptime(.{
            .{ "HS256", .HS256 },
            .{ "HS384", .HS384 },
            .{ "HS512", .HS512 },
            .{ "RS256", .RS256 },
            .{ "RS384", .RS384 },
            .{ "RS512", .RS512 },
            .{ "PS256", .PS256 },
            .{ "PS384", .PS384 },
            .{ "PS512", .PS512 },
            .{ "ES256", .ES256 },
            .{ "ES384", .ES384 },
            .{ "ES512", .ES512 },
            .{ "EdDSA", .EdDSA },
        });
        
        return algorithms.get(alg_str) orelse error.UnsupportedAlgorithm;
    }
    
    pub fn isHmac(self: Algorithm) bool {
        return switch (self) {
            .HS256, .HS384, .HS512 => true,
            else => false,
        };
    }
    
    pub fn isRsa(self: Algorithm) bool {
        return switch (self) {
            .RS256, .RS384, .RS512, .PS256, .PS384, .PS512 => true,
            else => false,
        };
    }
    
    pub fn isEcdsa(self: Algorithm) bool {
        return switch (self) {
            .ES256, .ES384, .ES512 => true,
            else => false,
        };
    }
    
    pub fn isEdDsa(self: Algorithm) bool {
        return switch (self) {
            .EdDSA => true,
            else => false,
        };
    }
};

/// Cryptographic key material
pub const Key = union(enum) {
    hmac: HmacKey,
    rsa: RsaKey,
    ecdsa: EcdsaKey,
    ed25519: Ed25519Key,
    
    pub const HmacKey = struct {
        secret: []const u8,
        
        pub fn fromBytes(secret: []const u8) HmacKey {
            return HmacKey{ .secret = secret };
        }
    };
    
    pub const RsaKey = struct {
        public_key: []const u8,  // PEM or DER format
        private_key: ?[]const u8, // PEM or DER format, null for verification-only
        key_size: u16, // Key size in bits
        
        pub fn fromPem(public_pem: []const u8, private_pem: ?[]const u8) !RsaKey {
            // In a real implementation, you'd parse the PEM and extract key size
            return RsaKey{
                .public_key = public_pem,
                .private_key = private_pem,
                .key_size = 2048, // Default, should be parsed from key
            };
        }
    };
    
    pub const EcdsaKey = struct {
        public_key: []const u8,
        private_key: ?[]const u8,
        curve: EcdsaCurve,
        
        pub const EcdsaCurve = enum {
            P256, // secp256r1
            P384, // secp384r1
            P521, // secp521r1
        };
        
        pub fn fromPem(public_pem: []const u8, private_pem: ?[]const u8, curve: EcdsaCurve) EcdsaKey {
            return EcdsaKey{
                .public_key = public_pem,
                .private_key = private_pem,
                .curve = curve,
            };
        }
    };
    
    pub const Ed25519Key = struct {
        public_key: [32]u8,
        private_key: ?[64]u8, // null for verification-only
        
        pub fn fromBytes(public_key: [32]u8, private_key: ?[64]u8) Ed25519Key {
            return Ed25519Key{
                .public_key = public_key,
                .private_key = private_key,
            };
        }
    };
};

/// Cryptographic signature
pub const Signature = struct {
    algorithm: Algorithm,
    data: []const u8,
    
    pub fn init(algorithm: Algorithm, data: []const u8) Signature {
        return Signature{
            .algorithm = algorithm,
            .data = data,
        };
    }
};

/// Security configuration for crypto operations
pub const SecurityConfig = struct {
    /// Allowed algorithms (empty means all supported algorithms allowed)
    allowed_algorithms: []const Algorithm = &.{},
    /// Minimum key sizes for RSA (default: 2048)
    min_rsa_key_size: u16 = 2048,
    /// Whether to enforce strict algorithm validation
    strict_validation: bool = true,
    /// Whether to allow none algorithm (should always be false in production)
    allow_none_algorithm: bool = false,
    
    pub fn isAlgorithmAllowed(self: SecurityConfig, algorithm: Algorithm) bool {
        if (self.allowed_algorithms.len == 0) {
            // If no specific algorithms are whitelisted, allow all supported ones
            return true;
        }
        
        for (self.allowed_algorithms) |allowed| {
            if (allowed == algorithm) return true;
        }
        
        return false;
    }
};

/// Cryptographic operations with security validation
pub const Crypto = struct {
    allocator: std.mem.Allocator,
    config: SecurityConfig,
    
    pub fn init(allocator: std.mem.Allocator, config: SecurityConfig) Crypto {
        return Crypto{
            .allocator = allocator,
            .config = config,
        };
    }
    
    /// Sign data with the given key and algorithm
    pub fn sign(self: *const Crypto, data: []const u8, key: Key, algorithm: Algorithm) ![]u8 {
        // Validate algorithm is allowed
        if (!self.config.isAlgorithmAllowed(algorithm)) {
            return error.AlgorithmNotAllowed;
        }
        
        // Validate key matches algorithm
        switch (algorithm) {
            .HS256, .HS384, .HS512 => {
                if (key != .hmac) return error.KeyAlgorithmMismatch;
                return try self.signHmac(data, key.hmac, algorithm);
            },
            .RS256, .RS384, .RS512, .PS256, .PS384, .PS512 => {
                if (key != .rsa) return error.KeyAlgorithmMismatch;
                if (key.rsa.private_key == null) return error.PrivateKeyRequired;
                if (key.rsa.key_size < self.config.min_rsa_key_size) return error.KeyTooSmall;
                return try self.signRsa(data, key.rsa, algorithm);
            },
            .ES256, .ES384, .ES512 => {
                if (key != .ecdsa) return error.KeyAlgorithmMismatch;
                if (key.ecdsa.private_key == null) return error.PrivateKeyRequired;
                return try self.signEcdsa(data, key.ecdsa, algorithm);
            },
            .EdDSA => {
                if (key != .ed25519) return error.KeyAlgorithmMismatch;
                if (key.ed25519.private_key == null) return error.PrivateKeyRequired;
                return try self.signEd25519(data, key.ed25519);
            },
        }
    }
    
    /// Verify signature with the given key and algorithm
    pub fn verify(self: *const Crypto, data: []const u8, signature: []const u8, key: Key, algorithm: Algorithm) !bool {
        // Validate algorithm is allowed
        if (!self.config.isAlgorithmAllowed(algorithm)) {
            return error.AlgorithmNotAllowed;
        }
        
        // Validate key matches algorithm
        switch (algorithm) {
            .HS256, .HS384, .HS512 => {
                if (key != .hmac) return error.KeyAlgorithmMismatch;
                return try self.verifyHmac(data, signature, key.hmac, algorithm);
            },
            .RS256, .RS384, .RS512, .PS256, .PS384, .PS512 => {
                if (key != .rsa) return error.KeyAlgorithmMismatch;
                if (key.rsa.key_size < self.config.min_rsa_key_size) return error.KeyTooSmall;
                return try self.verifyRsa(data, signature, key.rsa, algorithm);
            },
            .ES256, .ES384, .ES512 => {
                if (key != .ecdsa) return error.KeyAlgorithmMismatch;
                return try self.verifyEcdsa(data, signature, key.ecdsa, algorithm);
            },
            .EdDSA => {
                if (key != .ed25519) return error.KeyAlgorithmMismatch;
                return try self.verifyEd25519(data, signature, key.ed25519);
            },
        }
    }
    
    /// HMAC signing implementation
    fn signHmac(self: *const Crypto, data: []const u8, key: Key.HmacKey, algorithm: Algorithm) ![]u8 {
        switch (algorithm) {
            .HS256 => {
                var mac = std.crypto.auth.hmac.HmacSha256.init(key.secret);
                mac.update(data);
                const result = try self.allocator.alloc(u8, 32);
                mac.final(result);
                return result;
            },
            .HS384 => {
                var mac = std.crypto.auth.hmac.HmacSha384.init(key.secret);
                mac.update(data);
                const result = try self.allocator.alloc(u8, 48);
                mac.final(result);
                return result;
            },
            .HS512 => {
                var mac = std.crypto.auth.hmac.HmacSha512.init(key.secret);
                mac.update(data);
                const result = try self.allocator.alloc(u8, 64);
                mac.final(result);
                return result;
            },
            else => return error.InvalidAlgorithm,
        }
    }
    
    /// HMAC verification implementation (constant-time)
    fn verifyHmac(self: *const Crypto, data: []const u8, signature: []const u8, key: Key.HmacKey, algorithm: Algorithm) !bool {
        const expected_signature = try self.signHmac(data, key, algorithm);
        defer self.allocator.free(expected_signature);
        
        // Constant-time comparison
        if (signature.len != expected_signature.len) {
            return false;
        }
        
        return std.crypto.utils.timingSafeEql([*]const u8, signature.ptr, expected_signature.ptr, signature.len);
    }
    
    /// RSA signing implementation (placeholder - would need actual RSA implementation)
    fn signRsa(self: *const Crypto, data: []const u8, key: Key.RsaKey, algorithm: Algorithm) ![]u8 {
        _ = self;
        _ = data;
        _ = key;
        _ = algorithm;
        // In a real implementation, you would:
        // 1. Parse the RSA private key from PEM/DER
        // 2. Create the appropriate hash (SHA-256, SHA-384, or SHA-512)
        // 3. Apply PKCS#1 v1.5 or PSS padding
        // 4. Perform the RSA signature operation
        return error.NotImplemented;
    }
    
    /// RSA verification implementation (placeholder)
    fn verifyRsa(self: *const Crypto, data: []const u8, signature: []const u8, key: Key.RsaKey, algorithm: Algorithm) !bool {
        _ = self;
        _ = data;
        _ = signature;
        _ = key;
        _ = algorithm;
        // Similar to signing but with public key verification
        return error.NotImplemented;
    }
    
    /// ECDSA signing implementation (placeholder)
    fn signEcdsa(self: *const Crypto, data: []const u8, key: Key.EcdsaKey, algorithm: Algorithm) ![]u8 {
        _ = self;
        _ = data;
        _ = key;
        _ = algorithm;
        return error.NotImplemented;
    }
    
    /// ECDSA verification implementation (placeholder)
    fn verifyEcdsa(self: *const Crypto, data: []const u8, signature: []const u8, key: Key.EcdsaKey, algorithm: Algorithm) !bool {
        _ = self;
        _ = data;
        _ = signature;
        _ = key;
        _ = algorithm;
        return error.NotImplemented;
    }
    
    /// Ed25519 signing implementation
    fn signEd25519(self: *const Crypto, data: []const u8, key: Key.Ed25519Key) ![]u8 {
        if (key.private_key == null) return error.PrivateKeyRequired;
        
        const key_pair = std.crypto.sign.Ed25519.KeyPair{
            .public_key = std.crypto.sign.Ed25519.PublicKey{ .bytes = key.public_key },
            .secret_key = std.crypto.sign.Ed25519.SecretKey{ .bytes = key.private_key.?[0..32].* },
        };
        
        const signature = try key_pair.sign(data, null);
        const result = try self.allocator.alloc(u8, 64);
        @memcpy(result, &signature.bytes);
        return result;
    }
    
    /// Ed25519 verification implementation
    fn verifyEd25519(self: *const Crypto, data: []const u8, signature: []const u8, key: Key.Ed25519Key) !bool {
        _ = self;
        
        if (signature.len != 64) return false;
        
        const public_key = std.crypto.sign.Ed25519.PublicKey{ .bytes = key.public_key };
        const sig = std.crypto.sign.Ed25519.Signature{ .bytes = signature[0..64].* };
        
        public_key.verify(sig, data, null) catch return false;
        return true;
    }
};

/// Generate secure random bytes
pub fn randomBytes(allocator: std.mem.Allocator, count: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, count);
    std.crypto.random.bytes(bytes);
    return bytes;
}

/// Generate cryptographically secure random string (base64url encoded)
pub fn randomString(allocator: std.mem.Allocator, byte_count: usize) ![]u8 {
    const random_bytes = try randomBytes(allocator, byte_count);
    defer allocator.free(random_bytes);
    
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(random_bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, random_bytes);
    return encoded;
}

/// Generate SHA256 hash
pub fn sha256(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    
    const result = try allocator.alloc(u8, 32);
    @memcpy(result, &hash);
    return result;
}

/// Generate SHA256 hash and encode as base64url
pub fn sha256Base64Url(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const hash = try sha256(allocator, data);
    defer allocator.free(hash);
    
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(hash.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, hash);
    return encoded;
}

test "crypto algorithm parsing" {
    const testing = std.testing;
    
    // Test algorithm string conversion
    try testing.expectEqual(Algorithm.HS256, try Algorithm.fromString("HS256"));
    try testing.expectEqual(Algorithm.RS256, try Algorithm.fromString("RS256"));
    try testing.expectEqual(Algorithm.ES256, try Algorithm.fromString("ES256"));
    try testing.expectEqual(Algorithm.EdDSA, try Algorithm.fromString("EdDSA"));
    
    try testing.expectError(error.UnsupportedAlgorithm, Algorithm.fromString("none"));
    try testing.expectError(error.UnsupportedAlgorithm, Algorithm.fromString("HS128"));
    
    // Test algorithm type checking
    try testing.expect(Algorithm.HS256.isHmac());
    try testing.expect(!Algorithm.RS256.isHmac());
    try testing.expect(Algorithm.RS256.isRsa());
    try testing.expect(Algorithm.ES256.isEcdsa());
    try testing.expect(Algorithm.EdDSA.isEdDsa());
}

test "crypto random generation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test random bytes generation
    const bytes1 = try randomBytes(allocator, 32);
    defer allocator.free(bytes1);
    const bytes2 = try randomBytes(allocator, 32);
    defer allocator.free(bytes2);
    
    try testing.expect(bytes1.len == 32);
    try testing.expect(bytes2.len == 32);
    try testing.expect(!std.mem.eql(u8, bytes1, bytes2)); // Should be different
    
    // Test random string generation
    const str1 = try randomString(allocator, 16);
    defer allocator.free(str1);
    const str2 = try randomString(allocator, 16);
    defer allocator.free(str2);
    
    try testing.expect(!std.mem.eql(u8, str1, str2)); // Should be different
}

test "crypto HMAC operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = SecurityConfig{};
    const crypto = Crypto.init(allocator, config);
    
    const secret = "test_secret_key";
    const data = "test_data_to_sign";
    const key = Key{ .hmac = Key.HmacKey.fromBytes(secret) };
    
    // Test HMAC-SHA256 signing
    const signature = try crypto.sign(data, key, .HS256);
    defer allocator.free(signature);
    
    try testing.expect(signature.len == 32); // SHA256 produces 32 bytes
    
    // Test HMAC verification
    const valid = try crypto.verify(data, signature, key, .HS256);
    try testing.expect(valid);
    
    // Test invalid signature
    signature[0] ^= 1; // Flip a bit
    const invalid = try crypto.verify(data, signature, key, .HS256);
    try testing.expect(!invalid);
}

test "crypto security configuration" {
    const testing = std.testing;
    
    // Test default configuration (all algorithms allowed)
    const default_config = SecurityConfig{};
    try testing.expect(default_config.isAlgorithmAllowed(.HS256));
    try testing.expect(default_config.isAlgorithmAllowed(.RS256));
    
    // Test restricted configuration
    const restricted_config = SecurityConfig{
        .allowed_algorithms = &.{ .HS256, .RS256 },
    };
    try testing.expect(restricted_config.isAlgorithmAllowed(.HS256));
    try testing.expect(restricted_config.isAlgorithmAllowed(.RS256));
    try testing.expect(!restricted_config.isAlgorithmAllowed(.HS512));
}