/**
 * ── Fillr Frontend Environment Config ─────────────────────
 * Single source of truth for all environment-specific values.
 * Update these when switching between development / staging / production.
 */

const ENV = Object.freeze({
  /** Base URL for all API calls (no trailing slash) */
  API_URL: 'http://localhost:5000/api',

  /** Google OAuth 2.0 Client ID — must match GOOGLE_CLIENT_ID on the server */
  GOOGLE_CLIENT_ID: '555611983522-phrlkcadl138k2qe1oq27j3dhtuqliev.apps.googleusercontent.com',
});
