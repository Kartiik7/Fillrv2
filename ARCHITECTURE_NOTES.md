# Fillr — Architecture Notes

> **Generated:** 2026-07-02
> **Scope:** Every file wired into the running system (server, client, extension).

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Deployment & Configuration](#2-deployment--configuration)
3. [Backend — Node/Express API Server](#3-backend--nodeexpress-api-server)
4. [Web Client — Netlify Frontend](#4-web-client--netlify-frontend)
5. [Chrome Extension (Manifest V3)](#5-chrome-extension-manifest-v3)
6. [End-to-End Data Flow Diagrams](#6-end-to-end-data-flow-diagrams)
7. [Security Measures Summary](#7-security-measures-summary)

---

## 1. System Overview

Fillr is a placement-form autofill tool with three major layers that communicate over HTTPS:

```
Chrome Extension  <--> Backend API (Node/Express, Render)
Web Client (Netlify) <--> Backend API
Backend API <--> MongoDB Atlas
```

- **Backend** handles all auth, data persistence, admin, and field-mapping configuration.
- **Web client** is the primary user-facing dashboard (profile editor, key management, admin panel).
- **Extension** lives in Chrome, autofills forms using the user's saved profile data.

---

## 2. Deployment & Configuration

### Environment Variables (`server/.env`)

| Variable | Required | Purpose |
|---|---|---|
| `MONGO_URI` | Fatal | MongoDB Atlas connection string |
| `JWT_SECRET` | Fatal (>=32 chars) | Signs all JWTs |
| `PORT` | No (default 5000) | HTTP listen port |
| `NODE_ENV` | No | `production` / `development` |
| `GOOGLE_CLIENT_ID` | Warn-only | Google OAuth token verification |
| `RESEND_API_KEY` | Warn-only | Transactional email |
| `RESEND_FROM` | No | Sender address for emails |
| `FRONTEND_URL` | No | Used in reset / verify email links |
| `CORS_ORIGINS` | No | Extra allowed origins |
| `JWT_EXPIRY` | No (default `7d`) | JWT token lifetime |

### Client Config (`client/env.js`)

```js
ENV.API_URL          // https://fillrv2-ba1o.onrender.com/api
ENV.GOOGLE_CLIENT_ID // GCP OAuth client ID (must match server)
```

### Extension Config (`extension/env.js`)

```js
ENV.API_URL  // https://fillrv2-ba1o.onrender.com  (no /api suffix)
```

### Netlify Hosting (`netlify.toml`)

- Published directory: `client/`
- Clean URL rewrites: `/login` -> `pages/login/index.html`, etc.
- Caching: CSS/JS cached 1 year; HTML no-cache; images 30 days.
- Security headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.

---

## 3. Backend — Node/Express API Server

### Entry Point & Startup (`server/server.js`)

Boot sequence:
1. Load `.env` via dotenv
2. Fail fast if `MONGO_URI` or `JWT_SECRET` are missing / too short
3. Register process error handlers
4. Call `connectDB()` then start Express

### App-Level Middleware Stack (`server/src/app.js`)

Order: trust proxy -> helmet -> compression -> CORS -> body parsing -> mongoSanitize -> global rate limiter (100/15min) -> request counter -> routes -> 404 -> centralized error handler.

### Models (MongoDB / Mongoose)

**User** — central identity. Fields: email (unique, immutable), password (bcrypt, optional for Google users), authProvider, googleId (sparse unique), role (user/admin), isSuspended, profile (Mixed sub-documents), termsAccepted*, resetPasswordHash (select:false), verificationTokenHash (select:false), isVerified.

**ExtensionKey** — revocable secret keys. Fields: userId, keyId (UUIDv4), hashedKey (bcrypt), lookupHash (SHA-256 for O(1) lookup), deviceName, isActive, expiresAt (90 days), lastUsedAt. Max 5 active keys per user.

**FieldMapping** — admin-managed form field definitions. Fields: key, path, fieldType, primary[] (required, +5 score), secondary[] (+3), generic[] (+1), negative[] (-5), options (Map for select fields), orderGroup, order.

**AuditLog** — immutable admin action trail. Fields: action (UPPER_SNAKE_CASE), adminId, metadata (secrets stripped), ip, createdAt.

**SystemMetric** — one document per day (YYYY-MM-DD). Tracks: userRegistrations, loginRequests, extensionAuthRequests, passwordResetRequests, apiErrors, totalRequests, activeUsers[].

**LifetimeMetric** — singleton running totals. Avoids expensive aggregation over all daily docs.

**ConfigVersion** — singleton integer version bumped on every FieldMapping change. Extension uses this to skip re-fetching unchanged configs.

### Middleware

**authMiddleware** — verifies JWT, fetches live user from DB (catches deleted accounts), blocks suspended users, sets req.user.

**adminMiddleware** — runs after authMiddleware, checks req.user.role === 'admin'.

### Services

**logger** — leveled (error/warn/info/debug). Only warn+ in production.

**metricsService** — fire-and-forget `$inc` / `$addToSet` on SystemMetric + LifetimeMetric. Called from middleware and controllers.

**auditService** — fire-and-forget AuditLog.create(). Strips sensitive-sounding metadata keys (password, token, secret, hash, jwt, key) via camelCase segment analysis.

### Routes & Controllers

```
POST   /api/auth/register            authController.register
POST   /api/auth/login               authController.login
POST   /api/auth/google              authController.googleLogin
POST   /api/auth/extension           keyController.extensionAuth
POST   /api/auth/forgot-password     resetController.forgotPassword
POST   /api/auth/reset-password      resetController.resetPassword
GET    /api/auth/verify-email        verificationController.verifyEmail
POST   /api/auth/resend-verification verificationController.resendVerification

GET    /api/profile                  profileController.getProfile       [JWT]
PUT    /api/profile                  profileController.updateProfile    [JWT]
GET    /api/profile/my-data          profileController.getMyData        [JWT]

GET    /api/user/me                  userController.getMe               [JWT]
DELETE /api/user/delete              userController.deleteAccount       [JWT]

GET    /api/keys                     keyController.listKeys             [JWT]
POST   /api/keys/generate            keyController.generateKey          [JWT + pw confirm]
POST   /api/keys/rotate              keyController.rotateKey            [JWT + pw confirm]
POST   /api/keys/revoke              keyController.revokeKey            [JWT]

GET    /api/config/full              (public) version + mappings in one response
GET    /api/config/field-mappings    (public) mappings only (legacy)
GET    /api/config/version           (public) version only
GET    /api/config/meta              (public) lastUpdated timestamp

POST   /api/admin/field-mappings        upsert mapping     [JWT + admin]
PATCH  /api/admin/field-mappings/:key/reorder              [JWT + admin]
DELETE /api/admin/field-mappings/:key  delete mapping      [JWT + admin]
GET    /api/admin/users              paginated user list    [JWT + admin]
PATCH  /api/admin/users/:id/role     change role           [JWT + admin]
PATCH  /api/admin/users/:id/suspend  toggle suspension     [JWT + admin]
DELETE /api/admin/users/:id          hard delete user      [JWT + admin]
GET    /api/admin/metrics/summary    daily/weekly/lifetime [JWT + admin]
GET    /api/admin/audit-logs         paginated audit trail [JWT + admin]
GET    /api/admin/mappings/debug-match  label scoring tool [JWT + admin]

GET    /health                       DB readiness check (no auth)
```

---

## 4. Web Client — Netlify Frontend

Multi-page static site (plain HTML + vanilla JS). No build step.

- `client/env.js` — API_URL + GOOGLE_CLIENT_ID
- `client/js/api.js` — shared apiRequest() helper, reads JWT from localStorage
- `client/pages/` — home, login, register, dashboard, admin, field-mappings, forgot-password, reset-password, verify-email, terms, privacy

JWT stored in `localStorage`. All requests add `Authorization: Bearer <token>`.

---

## 5. Chrome Extension (Manifest V3)

### Security Architecture

All API calls go through `background.js` (service worker). Content scripts and popup never hold the JWT — they only receive sanitized profile data.

```
background.js (SW)     <-- message --> popup.js
background.js (SW)     <-- message --> content.js
background.js (SW)     -------HTTPS-----> API server
```

### background.js — Service Worker / API Proxy

- Stores JWT + API key in `chrome.storage.local` (not localStorage)
- On 401 response: re-auths via stored API key (POST /api/auth/extension), retries once
- Message handlers: FETCH_PROFILE, CHECK_AUTH, SAVE_API_KEY, SAVE_TOKEN, CLEAR_TOKEN, FETCH_FULL_CONFIG
- 15-second fetch timeout for Render free tier cold-start tolerance

### matcher.js — Pure Scoring Engine (content script 1)

Loaded before content.js. Pure functions, no DOM, no API:
- `normalizeLabel()` — lowercase, expand Roman numerals, %->percentage, strip punctuation
- `tokenize()` — normalize + split
- `calculateAdvancedScore(tokens, config)` — primary (+5), secondary (+3), generic (+1), negative (-5)
- `calculateOptionScore()` — fuzzy match dropdown options against canonical values + aliases

### content.js — Autofill Engine (content script 2)

- Auto-injected on docs.google.com/forms/*; on-demand via popup on other pages
- Scans DOM for inputs/selects/textareas + Google Forms custom elements
- Extracts label text from <label>, aria-label, placeholder, parent containers
- Scores each field against every mapping, fills best match above threshold
- UNSAFE_LABELS list prevents filling declaration/upload/signature fields
- Values set via element.value (never innerHTML)

### popup.js / popup.html — Extension UI

- Status indicator, API key setup, Scan/Autofill buttons, results, confirmations
- All API calls delegated to background.js via chrome.runtime.sendMessage

---

## 6. End-to-End Data Flow Diagrams

### Extension Autofill Flow

```
popup.js -> FETCH_PROFILE -> background.js -> GET /api/profile -> server -> MongoDB
         -> FETCH_FULL_CONFIG -> background.js -> GET /api/config/full -> server
         -> executeScript(content.js)
         -> AUTOFILL { profile, mappings } -> content.js
            content.js: scan DOM -> score fields -> set element.value
```

### Password Reset Flow

```
POST /forgot-password
  -> validate -> find user -> generate 256-bit token -> SHA-256 hash -> store in User
  -> respond immediately (generic message)
  -> sendResetEmailAsync() [fire-and-forget, 5s timeout, via Resend API]

POST /reset-password
  -> SHA-256(token) -> find user by hash + valid expiry
  -> set new password (bcrypt in pre-save hook) -> clear hash/expiry
```

### Extension Key Auth Flow

```
POST /api/auth/extension { apiKey }
  -> SHA-256(apiKey) -> findOne({ lookupHash, isActive, expiresAt > now })
  -> bcrypt.compare(apiKey, candidate.hashedKey)
  -> fallback: scan legacy keys (no lookupHash), bcrypt compare each, backfill lookupHash
  -> findById(userId) -> check isSuspended
  -> updateOne(lastUsedAt) [fire-and-forget]
  -> generateToken(userId) -> return JWT
```

---

## 7. Security Measures Summary

| Area | Measure |
|---|---|
| Passwords | bcrypt (10 rounds) in User pre-save hook. Never returned in responses. |
| JWTs | HS256, 7-day expiry, 32+ char secret enforced at startup. |
| Extension keys | bcrypt hash + SHA-256 lookup hash. Raw key shown once. 90-day expiry. Max 5/user. |
| Reset/verify tokens | crypto.randomBytes(32). Only SHA-256 hash stored. Single-use. 30min/24hr expiry. |
| NoSQL injection | mongoSanitize on req.body + req.params. Joi stripUnknown on all inputs. |
| Mass assignment | Explicit applyPicked() + sanitizeObject() — req.body never passed directly to DB. |
| Rate limiting | Global 100/15min. Auth 10/15min (failures only). Extension auth 5/15min. Key gen 10/hr. Admin 30/15min. |
| CORS | Strict whitelist. chrome-extension:// origins allowed. No wildcard. |
| Security headers | Helmet: CSP, HSTS (prod), X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| Email enumeration | Forgot-password + resend-verification always return identical generic messages. |
| Suspended accounts | Blocked at login AND on every protected request via authMiddleware. |
| Admin self-protection | Admins cannot change own role, suspend themselves, or delete themselves. |
| Token storage (extension) | JWT + API key in chrome.storage.local — never localStorage (page-accessible). |
| XSS in extension | Values injected via element.value not innerHTML. No eval(). Popup sanitizes all output via esc(). |
| Audit trail | All admin mutations + auth events logged to AuditLog. Secrets stripped from metadata. |
