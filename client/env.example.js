/**
 * ── Fillr Frontend Environment Config (EXAMPLE) ───────────
 * Copy this file to env.js and update with your values.
 * DO NOT commit env.js to version control!
 */

const ENV = Object.freeze({
  /** 
   * Base URL for all API calls (no trailing slash)
   * Development: http://localhost:5000/api
    * Production: https://fillrv2-ba1o.onrender.com/api
   */
  API_URL: 'http://localhost:5000/api',

  /** 
   * Google OAuth 2.0 Client ID
   * Get this from: https://console.cloud.google.com/apis/credentials
   * Must match GOOGLE_CLIENT_ID in server .env
   */
  GOOGLE_CLIENT_ID: 'your-google-client-id.apps.googleusercontent.com',
});
