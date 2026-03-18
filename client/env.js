/**
 * ── Fillr Frontend Environment Config ─────────────────────
 * Single source of truth for all environment-specific values.
 * Update these when switching between development / staging / production. * 
 * IMPORTANT: Copy from env.example.js and update with your values.
 * DO NOT commit this file with real credentials! */

const ENV = Object.freeze({
  /** Base URL for all API calls (no trailing slash) */
  /*API_URL: 'https://fillrv2.onrender.com/api',*/
  API_URL: 'https://fillrv2-ba1o.onrender.com/api',

  /** Google OAuth 2.0 Client ID — must match GOOGLE_CLIENT_ID on the server */
  GOOGLE_CLIENT_ID: '555611983522-phrlkcadl138k2qe1oq27j3dhtuqliev.apps.googleusercontent.com',
});
