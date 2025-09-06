Here’s how I’d approach it in Zig 0.16, with zsync for async:

What to build first (priority order)

OAuth2/OIDC RP (client)

Authorization Code + PKCE (must-have)

Discovery (.well-known/openid-configuration)

Token endpoint (access/refresh), refresh rotation

UserInfo endpoint

JWT validation (iss/aud/exp/nbf/iat, leeway) using JWKS cache + kid pinning

DPoP (optional, nice) and Nonce/State CSRF protection

Cookie helpers (SameSite=Lax/Strict, Secure, HttpOnly)

Session mgmt + backchannel logout (later)

Advanced OAuth2

Client Credentials (machine-to-machine)

PAR (Pushed Auth Requests) + JAR/JARM (Request/JWT)

mTLS-bound tokens (if you need high assurance)

Device Code flow (CLI/devices)

Token introspection & revocation

OIDC OP (identity provider) (later)

Issue ID tokens, JWKS rotation, consent pages

Backchannel/frontchannel logout

Federation features if needed

SAML 2.0 (last)

SP-initiated & IdP-initiated

XML Canonicalization, XML DSig/Enc (error-prone!)

Metadata, clock skew, replay protection

Sign/verify with RSA-SHA256 / ECDSA-SHA256

Strong XML parser and signature wrapping defenses

Architecture (keep it clean)

zid (module root)

http/ → use your zhttp client (H1/H2/H3) with zsync adapter

oauth/ → core OAuth2 (flows, token storage, refresh logic)

oidc/ → discovery, ID token validation, UserInfo

jose/ → JWT/JWS/JWE/JWK primitives

crypto/ → sign/verify wrappers (alg whitelist)

saml/ → XML, DSig, metadata (separate crate/module; optional)

store/ → in-mem + pluggable cache (redis/sql later)

time/ → monotonic + wall clock helpers with leeway

Async: provide *_Async adapters that return zsync.Task(T), but keep sync functions too.

Crypto reality (be careful)

JOSE must support: RS256/PS256/ES256/EdDSA (Ed25519) at minimum.

Zig std has solid hashing/HMAC; for RSA/ECDSA, plan either:

Pure Zig implementations you trust, or

Thin bindings to vetted libs (e.g., BoringSSL, OpenSSL, or a small audited Zig crypto package).

Implement alg allowlist (fail closed), crit header handling, and reject none.

JWKS cache with kid lookup, x5t/SKI optional, and key rotation (cache TTL, background refresh).

Constant-time compares for MACs; secure random via std.crypto.random.

Security must-haves

State + Nonce (CSRF + replay) per auth request

PKCE (S256) always for public clients

Clock skew tolerance (e.g., ±5m) on exp/nbf/iat

HTTPS only; enforce redirect URI exact match

Cookie flags: Secure, HttpOnly, SameSite=Lax (or Strict for highly sensitive flows)

Refresh token rotation (one-time use + detection of reuse)

Audience checks (access tokens) + azp/aud handling (OIDC)

Scopes minimal; allow app-level authorization checks

Replay defenses: store used nonces/jti (short TTL)

Minimal public API (RP client)
