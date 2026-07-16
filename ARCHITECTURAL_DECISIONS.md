# Fillr — Architectural Decision Analysis

> Each entry traces the decision back to real implementation files.

---

## 1. Authentication Mechanism

**Decision:** Three-tier auth — email/password (bcrypt + JWT), Google OAuth (server-side token verification), and a revocable hashed extension key that exchanges for a JWT.

**Implementation:**
- `authController.js` — `register`, `login`, `googleLogin`; `generateToken()` unified across all three paths.
- `keyController.js` — `extensionAuth()` does SHA-256 lookup -> bcrypt verify -> `generateToken()`.
- `authMiddleware.js` — all protected routes: `jwt.verify()` + live DB user fetch to catch deleted/suspended accounts.

**Why this approach exists:**
The extension runs in the background and must auth silently on every cold start without prompting for a password. A long-lived extension-specific key solves this. Unifying all three paths into the same JWT means every downstream middleware works identically regardless of how the session started.

**Alternatives considered:**

*Alternative A — Sessions / server-side cookies:* Store session IDs in express-session + Redis/MongoDB. Simpler revocation, but requires a session store, doesn't work cleanly for Chrome extensions (cross-origin cookie restrictions), and is stateful requiring sticky sessions for horizontal scaling.

*Alternative B — API keys only (no JWTs):* Issue one long-lived API key per user, verify with bcrypt on every request. Dead simple, but bcrypt at 10 rounds costs ~100ms per request — a DoS vector at any real load. The current design pays bcrypt cost once, then uses JWT.

**Tradeoff:** The three-tier system is more complex — two credential types, two Mongoose models, two rate limiters. The payoff is silent extension re-auth without bcrypt cost per API call, plus a standard OAuth flow for the web client.

---

## 2. JWT Storage Strategy (Extension vs. Web Client)

**Decision:** Extension stores JWT in `chrome.storage.local` (service worker only). Web client stores JWT in `localStorage`.

**Implementation:**
- `extension/background.js` — `getToken()`, `setToken()`, `clearToken()` all use `chrome.storage.local`.
- `client/js/api.js` line 9: `const token = localStorage.getItem('token');`
- `content.js` line 9 comment: "The token is NEVER passed to content scripts or the page context."

**Why this approach exists:**
`localStorage` is accessible to any JavaScript on the page including XSS payloads. `chrome.storage.local` is a privileged API only accessible within extension contexts. The background service worker acts as a security boundary — content scripts send messages, background makes authenticated calls, only sanitized profile data is returned.

**Alternatives considered:**

*Alternative A — HttpOnly cookies:* Browser attaches automatically, JavaScript can never read them. Best practice for web apps, but HttpOnly cookies cannot be reliably used from a Chrome extension service worker without explicit cookie API usage and complex CORS credential configuration.

*Alternative B — sessionStorage in extension popup:* Cleared when popup closes. Requires re-auth every popup open — UX unusable given popup opens on every user interaction.

**Tradeoff:** `localStorage` in the web client is a known XSS vulnerability. For a higher-security app this should be HttpOnly cookies. For this use case (student placement tool, Netlify static site) the risk is low and localStorage avoids CORS/credential complexity. The extension architecture is strong — service worker boundary provides genuine isolation.

---

## 3. Extension Key: bcrypt + SHA-256 Dual-Hash Design

**Decision:** Extension keys are stored as bcrypt hashes AND a SHA-256 "lookup hash" for O(1) candidate narrowing before bcrypt comparison.

**Implementation:**
- `ExtensionKey.js` — both `hashedKey` (bcrypt) and `lookupHash` (SHA-256, nullable for legacy).
- `keyController.js` `extensionAuth()` lines 291-323: fast path via lookupHash -> bcrypt; fallback scans legacy keys, backfills lookupHash.
- `keyController.js:38` — `const lookupHashOf = (key) => crypto.createHash('sha256').update(key).digest('hex');`

**Why this approach exists:**
bcrypt is intentionally slow (~100ms at 10 rounds). Without knowing which user the key belongs to, the naive approach would bcrypt-compare against all active keys system-wide. SHA-256 is fast (microseconds) and narrows the candidate set to exactly one before bcrypt takes over. The bcrypt step still happens, providing resistance against DB dump attacks.

**Alternatives considered:**

*Alternative A — Include userId in the auth request:* Client sends `{ userId, apiKey }`. Simpler schema, but leaks userId (attacker can enumerate users) and still requires bcrypt on up to 5 keys.

*Alternative B — SHA-256 as the sole storage hash:* Skip bcrypt entirely. O(1) lookup, zero compute cost. Catastrophically insecure against DB dumps — SHA-256 without a salt on a known key format is GPU-brute-forceable. bcrypt makes offline attacks ~10,000x more expensive per guess.

**Tradeoff:** Adds schema complexity (nullable `lookupHash`, two code paths for legacy/new keys). The benefit is O(1) lookup without compromising bcrypt's offline-brute-force resistance. Worth it at any meaningful scale; would be over-engineered for a few hundred users where O(n=5) bcrypt per auth is fast enough.

---

## 4. Async Email Delivery (Fire-and-Forget with Respond-First Pattern)

**Decision:** HTTP response is sent to the client *before* the email is dispatched. Email is sent async in a detached promise with a 5-second timeout.

**Implementation:**
- `resetController.js` lines 197-204:
  ```js
  res.json({ success: true, message: GENERIC_MSG }); // respond first
  sendResetEmailAsync(email, resetUrl).catch(...);    // then send email
  ```
- `verificationController.js` uses the identical pattern (lines 188-191).
- `sendResetEmailAsync` wraps `resend.emails.send()` in `Promise.race([..., timeout(5000)])`.

**Why this approach exists:**
Transactional email services have variable latency (100ms-2s) and can fail entirely. If the email call is awaited before responding, a Resend outage makes the reset endpoint appear broken. The user can't tell if the server received their request. By responding immediately, the endpoint is reliable from the user's perspective regardless of email health.

**Alternatives considered:**

*Alternative A — Await the email call before responding:* Dead simple. User waits the full Resend latency. If Resend is down, endpoint returns an error even though the token is stored — user may not know to retry, may think the whole reset failed.

*Alternative B — A proper job queue (BullMQ + Redis):* Enterprise-grade reliability with retries and dead-letter queues. Requires Redis, requires a long-running worker process (incompatible with Render free tier that spins down), significant operational complexity for one email per reset.

**Tradeoff:** Fire-and-forget has a real weakness: if email fails, the token is stored but the user doesn't know to retry, and there's no automatic retry. The code acknowledges this. Acceptable for a low-volume student tool. For a production SaaS, a job queue is worth the overhead.

---

## 5. MongoDB Schema Design — `profile` as Mixed / Schema-Free Sub-document

**Decision:** User profile sub-sections (personal, academics, ids, links, education, placement) are typed as `mongoose.Schema.Types.Mixed`, not strongly-typed nested schemas.

**Implementation:**
- `User.js` lines 44-104: each sub-section is `{ type: mongoose.Schema.Types.Mixed, default: { ... } }`.
- `profileController.js` line 23: validation done at Joi layer, not Mongoose schema layer.
- `FieldMapping.js` — canonical field definitions live here. New fields added by creating a FieldMapping document, no User schema change needed.

**Why this approach exists:**
Fillr is a dynamic autofill system — the profile field set grows as admins add new FieldMapping entries. A strict typed schema would require a schema migration + deployment for every new field. The Mixed type lets the profile store any key-value pairs that pass API-layer Joi validation, so new fields appear in user documents automatically.

**Alternatives considered:**

*Alternative A — Strict typed Mongoose schema for each field:* Full schema-level validation and autocompletion. But every new FieldMapping entry requires a schema update + deployment — the schema would perpetually lag the admin configuration. Also duplicates the field definition between User.js and the FieldMapping collection (two sources of truth).

*Alternative B — Separate Profile collection with key-value documents:* `{ userId, key: 'academics.cgpa', value: '8.5' }`. Perfectly dynamic. But fetching a full profile requires a collection scan filtered by userId — autofill needs many fields at once, making this expensive. Document-per-field is an anti-pattern for this access pattern.

**Tradeoff:** Mixed gives up Mongoose-level type enforcement and index-ability on profile sub-fields. Protection isn't gone — it's at the API layer (Joi + sanitizeObject). Main downside: MongoDB can't enforce type consistency if the API layer is bypassed (e.g. direct DB writes). Known and documented tradeoff since profile data must be plaintext for autofill.

---

## 6. ConfigVersion Singleton for Cache Invalidation

**Decision:** A single MongoDB document holds a monotonically incrementing integer. Every FieldMapping change bumps it. The extension fetches this version on each load and only re-processes mappings if the version changed.

**Implementation:**
- `ConfigVersion.js` — `bump()` uses `findOneAndUpdate({}, { $inc: { version: 1 } }, { upsert: true })`.
- `configRoutes.js` `GET /api/config/full` — returns version + mappings in one response.
- `adminRoutes.js` — every field mapping mutation calls `ConfigVersion.bump()`.
- Extension compares returned version to in-memory cache, skips re-processing if unchanged.

**Why this approach exists:**
The extension loads on every tab navigation to a Google Form. Without a version signal, it either always re-fetches all mappings (wasteful) or never re-fetches (stale). The version integer is a lightweight cache invalidation signal checked in the same request that returns the full config — zero extra network calls when unchanged, one call with fresh data when changed.

**Alternatives considered:**

*Alternative A — HTTP ETag / Last-Modified headers:* Standard HTTP caching protocol, no application-level tracking. But requires the extension to correctly store/send ETags, server to implement conditional GET logic. ETag is opaque to app logic; an integer version can be displayed in admin UIs and logged.

*Alternative B — Poll with a lastModified timestamp:* Already implemented as /api/config/meta. Clock skew between client and server causes spurious re-fetches. Two mapping changes within the same second could cause the extension to miss the second change (monotonic integers don't have this problem).

**Tradeoff:** The singleton integer is dead simple with no clock-skew issues. Minor weakness: ConfigVersion.bump() is called in the same handler as the mapping write — a small window where mapping is updated but version not yet bumped. Irrelevant in practice since both are fast MongoDB writes and the extension polls on load, not in real-time.

---

## 7. Rate Limiting Strategy — Per-Route Limits in Application Code

**Decision:** Layered rate limiting: a global limiter (100/15min) at app level, plus route-specific stricter limiters in each router file.

**Implementation:**
- `app.js` line 139: globalLimiter — 100/15min on all routes.
- `authRoutes.js`: authLimiter (10/15min, failures only), extensionAuthLimiter (5/15min), forgotLimiter (3/15min), resetLimiter (5/15min), verifyLimiter (3/15min).
- `keyRoutes.js`: keyGenLimiter (10/hr). `profileRoutes.js`: profileUpdateLimiter (20/15min).
- `userRoutes.js`: deleteLimiter (5/hr). `adminRoutes.js`: adminLimiter (30/15min).

**Why this approach exists:**
Different endpoints have different attack profiles. Login must resist credential stuffing (tight, failure-only so legit users aren't penalized). Extension key auth must resist bcrypt brute force (5/15min). Password reset resists email flooding (3/15min). A one-size-fits-all limit either locks out legitimate users on normal endpoints or underprotects sensitive ones.

**Alternatives considered:**

*Alternative A — Single conservative global limit (e.g. 20/15min):* Zero per-route config. Either too loose for auth (20 login attempts/15min is a lot for brute force) or too tight for general use (20 requests/15min breaks the dashboard if a user autosaves frequently).

*Alternative B — Rate limiting at the infrastructure layer (nginx, Cloudflare):* Language-agnostic, survives Node restarts. But cannot easily provide route-level granularity without complex config, requires infrastructure access not available on Render free tier, and moves security logic out of the reviewable codebase.

**Tradeoff:** Application-level rate limiting resets on server restart (in-memory store). On Render free tier, cold-starts happen frequently — an attacker who knows the deploy schedule could exploit this. A Redis-backed store (rate-limit-redis) would persist limits. For the current threat model (students), in-memory is sufficient and avoids Redis infrastructure.

---

## 8. NoSQL Injection Defense — Manual mongoSanitize.sanitize() Instead of Middleware

**Decision:** Instead of using express-mongo-sanitize as standard middleware, the sanitizer is called manually on req.body and req.params only, skipping req.query.

**Implementation:**
- `app.js` lines 131-135:
  ```js
  app.use((req, _res, next) => {
    if (req.body)   mongoSanitize.sanitize(req.body);
    if (req.params) mongoSanitize.sanitize(req.params);
    next();
  });
  ```
- Comment: "Express 5 makes req.query read-only, causing 'Cannot set property query' errors."

**Why this approach exists:**
express-mongo-sanitize normally wraps req.body, req.params, and req.query. Express 5 changed req.query to a read-only getter backed by a parsed URL — attempts to reassign its properties throw a runtime error. Calling sanitize() as a function directly bypasses the middleware's internal attempt to write to req.query.

**Alternatives considered:**

*Alternative A — Downgrade to Express 4:* Would allow standard middleware to work. Gives up Express 5 features (async error handling, named wildcard routes). Express 5 is the actively maintained version.

*Alternative B — Rely entirely on Joi validation, skip mongoSanitize:* Joi with stripUnknown removes all unrecognized fields. Simpler (one less middleware). But if a new controller forgets Joi validation, there's no fallback. mongoSanitize is defense-in-depth for that case.

**Tradeoff:** Correct and well-reasoned — navigates a real Express 5 compatibility issue without giving up the framework version or injection protection. The req.query gap is acceptable because query params going directly into MongoDB queries without Joi validation would be a separate bug, and this codebase doesn't do User.find(req.query)-style code.

---

## 9. RBAC — Binary Role System (user/admin) with Single Source of Truth

**Decision:** Roles defined in a frozen ROLES constant in User.js, exported and used by adminMiddleware. Only two roles. Role can only be changed via a dedicated admin endpoint.

**Implementation:**
- `User.js` lines 12-15: `const ROLES = Object.freeze({ USER: 'user', ADMIN: 'admin' })`.
- `adminMiddleware.js` line 29: `if (req.user.role !== ROLES.ADMIN)`.
- `adminRoutes.js` `PATCH /users/:id/role` — the only endpoint that can write the role field.
- No public endpoint touches role.

**Why this approach exists:**
Roles scattered as magic strings are impossible to audit — you can't grep for all role checks confidently. Exporting ROLES from User.js means one rename point if a role name changes. The single write endpoint for roles means the privilege escalation attack surface is one guarded route, not every endpoint that touches the user document.

**Alternatives considered:**

*Alternative A — Inline string checks (`req.user.role === 'admin'`):* Zero abstraction. A typo ('Admin' vs 'admin') silently bypasses the check. Adding a third role requires finding and updating every === check.

*Alternative B — Full RBAC library (casl, accesscontrol):* Fine-grained per-resource, per-action control. Significant abstraction overhead and a non-trivial dependency for a two-role system.

**Tradeoff:** Appropriately scoped. The code documents the extension point explicitly. The ROLES constant pattern scales to 3-5 roles without architectural changes.

---

## 10. Extension Auth Architecture — Background Service Worker as API Proxy

**Decision:** All authenticated API calls from the extension go through background.js. Content scripts and popup never make API calls directly and never hold the JWT.

**Implementation:**
- `background.js` lines 1-24: architectural rationale comment.
- `background.js` lines 222-298: message router for FETCH_PROFILE, FETCH_FULL_CONFIG, etc.
- `content.js` lines 8-12: "No access to JWT or API key."
- `popup.js` line 18: "All API communication goes through background.js."

**Why this approach exists:**
Content scripts run in an isolated world with DOM access. By keeping the JWT in the service worker (no DOM access, unreachable by page JavaScript) and having it make the network call, the token never crosses into page-accessible territory. If a malicious page intercepts the profile data, they learn the user's CGPA — not their authentication token.

**Alternatives considered:**

*Alternative A — Content script makes API calls directly:* Eliminates message-passing overhead. The architectural discipline of "no JWT in content script" is easier to enforce than "content script can have JWT but must never expose it."

*Alternative B — Popup makes all API calls (no background proxy):* Works while popup is open. Popup closes immediately after user clicks autofill — content script injection is async. If popup closes before content script responds, communication channel is lost. Background service workers persist independently of popup lifecycle.

**Tradeoff:** Message-passing adds latency (one extra IPC round-trip per call) and code complexity (message type routing, async return true pattern). The security benefit is real and worth it for an extension that operates on potentially untrusted form pages.

---

## 11. Database Choice — MongoDB vs. Relational

**Decision:** MongoDB via Mongoose as sole data store. No relational DB, no Redis, no search index.

**Implementation:**
- `db.js` — single Mongoose connection.
- All models use Mongoose ODM. SystemMetric / LifetimeMetric use `$inc` upserts for atomic counter increments.

**Why this approach exists:**
The user profile has a variable, admin-defined structure (Mixed fields). A relational schema would require a wide table with many nullable columns, or an EAV (entity-attribute-value) table notoriously awkward to query. MongoDB's document model maps directly to the JSON object the extension reads — no JOIN, no ORM translation. `$inc` handles atomic counter increments without transactions.

**Alternatives considered:**

*Alternative A — PostgreSQL with JSONB column:* JSONB gives document flexibility with relational guarantees, full ACID transactions, FK constraints between users and extension_keys, index into JSONB fields. More complex query syntax; requires a hosted Postgres instance (Atlas free tier is more accessible).

*Alternative B — SQLite:* No network round-trip. Cannot run on multiple instances (file locking). Render free tier uses ephemeral storage — file disappears on each deploy. Not viable for cloud deployment without persistent volumes.

**Tradeoff:** MongoDB fits the schema flexibility requirement well. The downside is weak cross-collection consistency — no FK constraint ensuring ExtensionKey.userId points to a real User. User deletion in userController manually deletes extension keys first (correct but fragile — any code path that deletes a user without going through that controller leaves orphaned keys). PostgreSQL would enforce this at the DB level.

---

## 12. Email Service — Resend API vs. Self-Hosted SMTP

**Decision:** Transactional email uses the Resend API, initialized at module load in resetController.js and verificationController.js.

**Implementation:**
- `resetController.js` lines 45-46: `const resend = new Resend(process.env.RESEND_API_KEY || '');`
- Both controllers: check HAS_RESEND_KEY, fall back to console logging in development.
- 5-second Promise.race timeout prevents hanging on Resend outages.

**Why this approach exists:**
Raw SMTP requires managing TLS, auth, retry logic, bounce handling, and deliverability reputation (SPF/DKIM/DMARC). Resend handles all of this. The absent-key path (console log in dev) means the full stack works locally without email credentials.

**Alternatives considered:**

*Alternative A — nodemailer with Gmail SMTP:* Free for low volume. Gmail has strict daily limits (500/day) and will throttle bulk-looking sends. Requires DKIM config to avoid spam folders. Manual credential rotation.

*Alternative B — Return reset link in the API response:* Zero email dependency. Fundamentally insecure — the reset link in a response can be read by network proxies or interceptors. The point of email delivery is that only the inbox owner can see the link.

**Tradeoff:** Resend is the right call at this scale. Only risk is vendor dependency. Code is reasonably isolated — Resend client instantiated in two controller files, email logic in one helper function each. Switching providers requires changes in two files. Slight improvement: extract into a single emailService.js (currently minor duplication).

---

## 13. Profile Validation — Joi + Business Rules Layer

**Decision:** Profile updates go through two validation stages: Joi schema validation (structure + type), then `validateProfileBusinessRules()` (semantic domain rules).

**Implementation:**
- `profileController.js` lines 29-38: profileUpdateSchema — Joi with `.pattern(fieldPattern, fieldValue)` for dynamic field acceptance.
- `profileController.js` lines 94-142: validateProfileBusinessRules() — age > 0, percentages 0-100, CGPA 0-10, gap 0-12, PG-specific required fields.
- Applied in updateProfile (lines 186-199): Joi first, business rules second.

**Why this approach exists:**
Joi validates structure and types but doesn't understand domain semantics like "CGPA can't be negative" or "PG students must provide UG degree information." Separating into two layers keeps each focused: Joi enforces the schema contract, business rules enforce application correctness. Business rules can also be tested independently.

**Alternatives considered:**

*Alternative A — Encode all rules in Joi using .custom() validators:* Single validation stage. Works only if schema is fully typed. With Mixed fields and dynamic field names, Joi's .pattern() approach can't easily add per-field numeric range checks. Cross-field rules (PG needing UG fields) are awkward in Joi.

*Alternative B — Mongoose validators:* Add validate callbacks to each profile sub-field. Impossible with Mixed typed fields — Mongoose doesn't validate Mixed internals. Would require switching to a strongly typed schema.

**Tradeoff:** Two-layer approach is the right fit given the Mixed schema. Business rules function is clear imperative code. Weakness: it must be kept in sync with FieldMapping entries manually — if an admin adds a new `cgpa_weighted` field, the business rules function won't know to validate its range. Improvement: drive validation rules from FieldMapping schema metadata, making it self-updating.
