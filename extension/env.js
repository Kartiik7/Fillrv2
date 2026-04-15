/**
 * ── Fillr Extension Environment Config ────────────────────
 * Single source of truth for all environment-specific values.
 * Loaded by background.js (importScripts) and popup.html (<script>). * 
 * IMPORTANT: Copy from env.example.js and update with your values.
 * DO NOT commit this file with real credentials! */

// Using var (not const) so importScripts in service worker doesn't throw on re-import.
// eslint-disable-next-line no-unused-vars
var ENV = Object.freeze({
  /** Backend base URL (no trailing slash, no /api suffix) */
  API_URL: 'https://fillrv2-ba1o.onrender.com',
});
