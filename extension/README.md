# Fillr – Placement Form Autofill (Chrome Extension)

A Chrome Extension (Manifest V3) that automatically detects and fills placement/recruitment form fields with your saved profile data. Works with Google Forms and standard HTML forms.

## Features

- **Smart field detection** — Weighted keyword matching with confidence scoring
- **Google Forms support** — Click simulation for custom dropdowns and radio groups
- **Adaptive memory** — Learns field mappings per domain for faster future fills
- **Secure auth** — Extension secret key → JWT exchange; token never leaves background worker
- **Confirmation flow** — Medium-confidence matches require user approval before filling

## Security Architecture

| Layer | Protection |
|-------|-----------|
| **Token storage** | JWT in `chrome.storage.local` only — never `localStorage`, never page context |
| **API proxy** | All authenticated requests go through `background.js` service worker |
| **Content isolation** | Content script runs in isolated world; page JS cannot access extension APIs |
| **Input sanitization** | All dynamic HTML uses `esc()` helper to prevent XSS |
| **Permissions** | Minimal: `activeTab`, `scripting`, `storage`. No `<all_urls>` |
| **Host permissions** | Restricted to backend API domain + `docs.google.com/forms/*` |
| **CSP** | `script-src 'self'; object-src 'none'` — no inline JS, no eval |

## Installation

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. Pin the extension for quick access

## Usage

1. Generate an Extension Secret Key from the Fillr dashboard
2. Click the extension icon → paste your key → **Connect**
3. Navigate to a placement form (Google Forms or standard HTML)
4. Click **Autofill Page** — high-confidence fields fill automatically
5. Review and confirm medium-confidence matches

## File Structure

```
extension/
├── manifest.json    # MV3 manifest — permissions, CSP, content script config
├── background.js    # Service worker — API proxy, token management, message router
├── content.js       # Form detection & autofill engine (injected into pages)
├── popup.html       # Extension popup UI
├── popup.js         # Popup logic — scan, autofill, auth, learned mappings
├── styles.css       # Popup styles (Fillr design system)
├── env.js           # Environment config (API URL)
└── ICONS_README.md  # Instructions for creating extension icons
```

## Environment

Edit `env.js` to change the backend API URL:

```js
var ENV = Object.freeze({
  API_URL: 'https://fillr-gqyp.onrender.com',
});
```
