/**
 * background.js — Secure API proxy service worker (Manifest V3)
 *
 * Security architecture:
 *  - Token storage:    JWT lives exclusively in chrome.storage.local (not localStorage,
 *                      not sessionStorage, not injected into page context).
 *  - API proxy:        All authenticated API calls are made FROM this background
 *                      service worker. The token is NEVER passed to content scripts
 *                      or the page context — prevents XSS token theft.
 *  - No page injection: Token is retrieved here and used here. Content scripts
 *                       only receive sanitized profile data, never the raw token.
 *  - No sensitive logs: No PII or token values are written to console.
 *  - Extension key:    The raw API key is used ONCE to obtain a JWT via
 *                      POST /api/auth/extension. The JWT is then stored. The raw
 *                      key remains in storage for re-auth if the JWT expires.
 *
 * Protects against:
 *  - XSS token theft:    Token never reaches page context or content script
 *  - CORS bypass:        API calls from background bypass page-level CORS restrictions
 *                        while still being subject to server-side CORS policy
 *  - Token leakage:      No console.log of token or profile PII values
 *  - Credential replay:  Token expiry enforced by server; 401 triggers re-auth via key
 *  - Key leakage:        Raw key stored in chrome.storage.local only (not page-accessible)
 */

importScripts('env.js');
const API_URL = ENV.API_URL;

// ── Secure storage accessors ──────────────────────────────────
// Token + API key live only in chrome.storage.local — never localStorage.
// (localStorage is accessible to page scripts; chrome.storage.local is not)

const getToken = () =>
  new Promise((resolve) => {
    chrome.storage.local.get(['jwtToken'], (result) => resolve(result.jwtToken || null));
  });

const setToken = (token) =>
  new Promise((resolve) => {
    chrome.storage.local.set({ jwtToken: token }, resolve);
  });

const clearToken = () =>
  new Promise((resolve) => {
    chrome.storage.local.remove(['jwtToken'], resolve);
  });

const getApiKey = () =>
  new Promise((resolve) => {
    chrome.storage.local.get(['extensionApiKey'], (result) => resolve(result.extensionApiKey || null));
  });

const setApiKey = (key) =>
  new Promise((resolve) => {
    chrome.storage.local.set({ extensionApiKey: key }, resolve);
  });

const clearApiKey = () =>
  new Promise((resolve) => {
    chrome.storage.local.remove(['extensionApiKey'], resolve);
  });

// ── Fetch with timeout ────────────────────────────────────────────
// Prevents hanging requests on slow/cold-start backends (Render free tier).
// Default timeout: 15 seconds.
const FETCH_TIMEOUT_MS = 15_000;

const fetchWithTimeout = (url, options = {}) => {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(id));
};

// ── Extension key → JWT exchange ──────────────────────────────────
// Uses the stored raw API key to obtain a fresh JWT via POST /api/auth/extension.
// Protects against: stale JWT reuse — always gets a fresh token from server.
const authenticateWithKey = async () => {
  const apiKey = await getApiKey();
  if (!apiKey) throw Object.assign(new Error('No API key stored.'), { code: 'NO_KEY' });

  const response = await fetchWithTimeout(`${API_URL}/api/auth/extension`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey }),
  });

  const data = await response.json();

  if (!response.ok) {
    // If key is invalid/expired/revoked, clear it
    if (response.status === 401) {
      await clearApiKey();
      await clearToken();
    }
    throw new Error(data.message || 'Extension authentication failed.');
  }

  // Store the fresh JWT
  await setToken(data.accessToken);
  return data.accessToken;
};

// ── Authenticated API proxy ───────────────────────────────────
// All API calls are made FROM background — token never travels to page context.
// If JWT is expired or missing, attempts automatic re-auth via extension key.

const apiRequest = async (endpoint, options = {}) => {
  let token = await getToken();

  // If no token, try to get one via extension key
  if (!token) {
    try {
      token = await authenticateWithKey();
    } catch (err) {
      throw Object.assign(new Error('Not authenticated. Please set up your extension key.'), { code: 'NO_TOKEN' });
    }
  }

  const doFetch = async (authToken) => {
    return fetchWithTimeout(`${API_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
        ...(options.headers || {}),
      },
    });
  };

  let response = await doFetch(token);

  // If 401, try re-auth via extension key once (handles expired JWT)
  if (response.status === 401) {
    try {
      token = await authenticateWithKey();
      response = await doFetch(token);
    } catch (err) {
      await clearToken();
      throw Object.assign(new Error('Session expired. Please re-authenticate.'), { code: 'UNAUTHORIZED' });
    }
  }

  if (response.status === 401) {
    await clearToken();
    throw Object.assign(new Error('Session expired. Please log in again.'), { code: 'UNAUTHORIZED' });
  }

  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'API request failed.');
  return data;
};

// ── Message router ────────────────────────────────────────────
// Popup and content scripts communicate through here.
// They receive sanitized results — never the raw token or API key.
//
// Security: chrome.runtime.onMessage only fires for messages sent by
// extension pages (popup, content scripts, other extension scripts).
// Web page JS cannot send messages to this listener unless the extension
// explicitly uses chrome.runtime.onMessageExternal (which we don't).
// Defence-in-depth: we also verify sender.id matches our own extension.

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  // Defence-in-depth: reject messages from other extensions / external sources
  if (_sender.id !== chrome.runtime.id) {
    sendResponse({ success: false, message: 'Unauthorized sender.' });
    return;
  }

  switch (request.type) {

    case 'FETCH_PROFILE':
      // Popup requests profile — we fetch it here using the stored token
      apiRequest('/api/profile')
        .then((data) => sendResponse({ success: true, data }))
        .catch((err) => sendResponse({ success: false, message: err.message, code: err.code }));
      return true; // Keep channel open for async response

    case 'CHECK_AUTH':
      // Check if a token or API key exists (does not validate with server)
      Promise.all([getToken(), getApiKey()])
        .then(([token, key]) => sendResponse({ authenticated: !!(token || key) }))
        .catch(() => sendResponse({ authenticated: false }));
      return true;

    case 'SAVE_API_KEY':
      // Save extension API key and immediately authenticate
      (async () => {
        try {
          await setApiKey(request.apiKey);
          await authenticateWithKey();
          sendResponse({ success: true });
        } catch (err) {
          await clearApiKey();
          sendResponse({ success: false, message: err.message });
        }
      })();
      return true;

    case 'SAVE_TOKEN':
      // Direct JWT save (backward compat — e.g., from web login)
      setToken(request.token)
        .then(() => sendResponse({ success: true }))
        .catch(() => sendResponse({ success: false }));
      return true;

    case 'CLEAR_TOKEN':
      // Explicit logout — remove token and API key from storage
      Promise.all([clearToken(), clearApiKey()])
        .then(() => sendResponse({ success: true }))
        .catch(() => sendResponse({ success: false }));
      return true;

    // ── Field mapping config (public, no auth) ──────────────
    case 'FETCH_FULL_CONFIG':
      // Fetches version + mappings in a single HTTP request.
      // Replaces the old two-trip pattern (FETCH_CONFIG_VERSION → FETCH_FIELD_MAPPINGS).
      // content.js compares the returned version against its cached value and
      // skips re-processing when the version is unchanged.
      // No auth required — read-only public config.
      fetchWithTimeout(`${API_URL}/api/config/full`)
        .then((r) => r.json())
        .then((data) => sendResponse(data))
        .catch((err) => sendResponse({ success: false, message: err.message }));
      return true;

    default:
      sendResponse({ status: 'received' });
      return true;
  }
});

// ── Extension lifecycle ───────────────────────────────────────
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    // First install — no sensitive data logged
  }
});
