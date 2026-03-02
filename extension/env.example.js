/**
 * ── Fillr Extension Environment Config (EXAMPLE) ──────────
 * Copy this file to env.js and update with your values.
 * DO NOT commit env.js to version control!
 * 
 * This file is loaded by:
 * - background.js (via importScripts)
 * - popup.html (via <script> tag)
 */

// Using var (not const) so importScripts in service worker doesn't throw on re-import.
// eslint-disable-next-line no-unused-vars
var ENV = Object.freeze({
  /** 
   * Backend API base URL (no trailing slash, no /api suffix)
   * Development: http://localhost:5000
   * Production: https://fillrv2.onrender.com
   */
  API_URL: 'http://localhost:5000',
});
