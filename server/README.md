# Fillr — Server

Express.js REST API for the Fillr placement form autofill system.

## Architecture

```
server/
├── server.js               # Entry point — env validation, DB connect, listen
└── src/
    ├── app.js              # Express app — middleware, routes, error handler
    ├── config/
    │   ├── config.js       # Centralized tunable constants (metrics whitelist, JWT expiry, etc.)
    │   └── db.js           # MongoDB connection via Mongoose
    ├── controllers/        # HTTP handler logic (Joi validation → DB query → response)
    │   ├── authController.js
    │   ├── keyController.js
    │   ├── profileController.js
    │   ├── resetController.js
    │   ├── userController.js
    │   └── verificationController.js
    ├── middleware/
    │   ├── authMiddleware.js   # JWT verify → attach req.user
    │   └── adminMiddleware.js  # Require role === 'admin'
    ├── models/             # Mongoose schemas
    │   ├── AuditLog.js
    │   ├── ConfigVersion.js
    │   ├── ExtensionKey.js
    │   ├── FieldMapping.js
    │   ├── SystemMetric.js
    │   └── User.js
    ├── routes/             # Express routers — apply rate limits, auth, call controllers
    │   ├── adminRoutes.js
    │   ├── authRoutes.js
    │   ├── configRoutes.js
    │   ├── keyRoutes.js
    │   ├── profileRoutes.js
    │   └── userRoutes.js
    ├── services/           # Reusable business logic (fire-and-forget, no HTTP)
    │   ├── auditService.js
    │   ├── logger.js
    │   └── metricsService.js
    └── tests/              # Jest unit tests
        ├── authController.test.js
        ├── logger.test.js
        └── metricsService.test.js
```

## Security Design

| Layer         | Mechanism |
|---------------|-----------|
| Transport     | HTTPS (enforced in production via HSTS) |
| Auth          | JWT (HS256, 7d expiry, verified per-request) |
| CORS          | Strict origin whitelist (env `ALLOWED_ORIGINS`) |
| Rate Limiting | Per-route limiters (auth: 10/15min, global: 100/15min) |
| Input         | Joi validation on all write endpoints |
| Injection     | express-mongo-sanitize strips `$`/`.` keys |
| Headers       | Helmet: CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Errors        | Centralized handler — no stack traces in production |
| Logging       | Structured logger — no `console.*` in production |
| Audit         | AuditLog collection — admin + user-level actions |

## Environment Variables

| Variable         | Required | Description |
|------------------|----------|-------------|
| `MONGO_URI`      | ✅       | MongoDB connection string |
| `JWT_SECRET`     | ✅       | ≥32 char secret for JWT signing |
| `NODE_ENV`       | —        | `production` or `development` (default: development) |
| `PORT`           | —        | HTTP port (default: 5000) |
| `ALLOWED_ORIGINS`| Prod ✅  | Comma-separated CORS origins |
| `RESEND_API_KEY` | —        | Resend API key for email (optional in dev) |
| `RESEND_FROM`    | —        | Sender address for emails |
| `FRONTEND_URL`   | —        | Frontend base URL for email links |
| `GOOGLE_CLIENT_ID`| —       | Google OAuth client ID |

## Running

```bash
# Development (auto-restart on change)
npm run dev

# Production
NODE_ENV=production npm start

# Tests
npm test
```

## API Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | — | Register new user |
| POST | `/api/auth/login` | — | Login with email/password |
| POST | `/api/auth/google` | — | Google OAuth login |
| POST | `/api/auth/forgot-password` | — | Send reset email |
| POST | `/api/auth/reset-password` | — | Complete password reset |
| GET | `/api/profile` | JWT | Get user profile |
| PUT | `/api/profile` | JWT | Update user profile |
| GET | `/api/user/me` | JWT | GDPR: Get all user data |
| DELETE | `/api/user/delete` | JWT | GDPR: Delete account |
| GET | `/api/config/field-mappings` | — | Get extension field mappings |
| GET | `/api/config/version` | — | Get config version |
| GET | `/api/keys` | JWT | List extension keys |
| POST | `/api/keys/generate` | JWT | Generate new key |
| POST | `/api/keys/rotate` | JWT | Rotate key |
| POST | `/api/keys/revoke` | JWT | Revoke key |
| GET | `/api/admin/users` | JWT+Admin | List users |
| PATCH | `/api/admin/users/:id/role` | JWT+Admin | Change user role |
| PATCH | `/api/admin/users/:id/suspend` | JWT+Admin | Toggle suspend |
| DELETE | `/api/admin/users/:id` | JWT+Admin | Delete user |
| GET | `/api/admin/field-mappings` | JWT+Admin | List field mappings |
| POST | `/api/admin/field-mappings` | JWT+Admin | Create/update mapping |
| DELETE | `/api/admin/field-mappings/:key` | JWT+Admin | Delete mapping |
| GET | `/api/admin/metrics/summary` | JWT+Admin | Usage metrics |
| GET | `/api/admin/audit-logs` | JWT+Admin | Audit log |
| GET | `/health` | — | Health check |
