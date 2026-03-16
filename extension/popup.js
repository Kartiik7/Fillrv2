/**
 * Popup Script - UI Logic and Messaging
 * Handles user interactions and communication with content script
 */

// DOM Elements
const scanBtn = document.getElementById('scanBtn');
const autofillBtn = document.getElementById('autofillBtn');
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const resultsSection = document.getElementById('resultsSection');
const resultsContent = document.getElementById('resultsContent');
const tokenInput = document.getElementById('tokenInput');
const saveTokenBtn = document.getElementById('saveTokenBtn');
const confirmationsSection = document.getElementById('confirmationsSection');
const confirmationsContent = document.getElementById('confirmationsContent');

// ── Security: no direct API calls from popup ──────────────────
// All API communication goes through background.js to prevent
// token exposure in popup context. See FETCH_PROFILE message.

/**
 * Sanitize a string for safe insertion into innerHTML.
 * Prevents XSS from page titles, field labels, or any external text.
 * @param {string} str - Untrusted string
 * @returns {string} HTML-escaped string
 */
const esc = (str) => {
  if (!str) return '';
  const el = document.createElement('span');
  el.textContent = String(str);
  return el.innerHTML;
};

/**
 * Show toast notification (replaces alert() for better UX)
 * @param {string} message - Message to display
 * @param {string} type - 'success', 'error', or 'warn'
 * @param {number} duration - Duration in ms (default: 3000)
 */
const showToast = (message, type = 'success', duration = 3000) => {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = `toast ${type} show`;
  
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => {
    toast.className = 'toast';
  }, duration);
};

/**
 * Show/hide pending confirmations banner
 * @param {number} count - Number of pending confirmations
 */
const updatePendingBanner = (count) => {
  const banner = document.getElementById('pendingBanner');
  const countEl = document.getElementById('pendingCount');
  
  if (count > 0) {
    countEl.textContent = `${count} field${count > 1 ? 's' : ''} need review ↓`;
    banner.style.display = 'flex';
  } else {
    banner.style.display = 'none';
  }
};

// Store pending confirmations and profile globally
let pendingConfirmationsData = [];
let currentProfile = null;
let currentFieldMap = {};

/**
 * Safely resolve a nested value from an object by dot-path
 * @param {Object} obj - Source object
 * @param {string} path - Dot separated path
 * @returns {any} Resolved value or null
 */
const getValueByPath = (obj, path) => {
  if (!obj || !path) return null;
  return path.split('.').reduce((acc, part) => {
    if (acc === null || acc === undefined) return null;
    return acc[part];
  }, obj) ?? null;
};

/**
 * Convert config payload into lookup map: key -> { path }
 * @param {Object} response - FETCH_FULL_CONFIG response
 * @returns {Object} Lookup map
 */
const buildFieldMapLookup = (response) => {
  if (!response || !response.success) return {};

  const source = response.mappings;
  const map = {};

  if (Array.isArray(source)) {
    source.forEach((entry) => {
      if (entry && entry.key && entry.path) {
        map[entry.key] = { path: entry.path };
      }
    });
    return map;
  }

  if (source && typeof source === 'object') {
    Object.entries(source).forEach(([key, value]) => {
      if (key && value && value.path) {
        map[key] = { path: value.path };
      }
    });
  }

  return map;
};

/**
 * Fetch field mappings from backend (via background proxy)
 * and cache them for confirmation dropdown rendering.
 * @returns {Promise<Object>} key -> { path }
 */
const ensureFieldMap = async () => {
  if (Object.keys(currentFieldMap).length > 0) {
    return currentFieldMap;
  }

  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'FETCH_FULL_CONFIG' }, (res) => {
      currentFieldMap = buildFieldMapLookup(res);
      resolve(currentFieldMap);
    });
  });
};

/**
 * Resolve profile value for a selected mapping key.
 * @param {string} selectedKey - FIELD_MAP key
 * @returns {string} Resolved display value
 */
const resolveProfileValueForKey = (selectedKey) => {
  if (!selectedKey || !currentProfile) return '';
  const path = currentFieldMap[selectedKey]?.path;
  if (!path) return '';
  const value = getValueByPath(currentProfile, path);
  return value === null || value === undefined ? '' : String(value);
};

/**
 * Highlight a field on the page by sending message to content script
 * @param {string} fieldId - The field ID to highlight
 */
const highlightFieldOnPage = async (fieldId) => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.sendMessage(tab.id, {
      action: 'HIGHLIGHT_FIELD',
      fieldId: fieldId
    });
  } catch (err) {
    console.error('Failed to highlight field:', err);
  }
};

/**
 * Highlight all pending confirmation fields on the page
 */
const highlightAllPendingFields = async () => {
  if (!pendingConfirmationsData || pendingConfirmationsData.length === 0) return;
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const fieldIds = pendingConfirmationsData.map(conf => conf.fieldId);
    await chrome.tabs.sendMessage(tab.id, {
      action: 'HIGHLIGHT_ALL_FIELDS',
      fieldIds: fieldIds
    });
  } catch (err) {
    console.error('Failed to highlight fields:', err);
  }
};

/**
 * Adaptive Memory System - Helper Functions
 */

/**
 * Get current domain from active tab
 * @returns {Promise<string|null>} Domain name or null
 */
const getCurrentDomain = () => {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        try {
          const url = new URL(tabs[0].url);
          resolve(url.hostname);
        } catch (error) {
          resolve(null);
        }
      } else {
        resolve(null);
      }
    });
  });
};

/**
 * Get all site mappings from storage
 * @returns {Promise<Object>} Site mappings object
 */
const getSiteMappings = () => {
  return new Promise((resolve) => {
    chrome.storage.local.get(['siteMappings'], (result) => {
      resolve(result.siteMappings || {});
    });
  });
};

/**
 * Save a single mapping for a domain
 * @param {string} domain - Domain name
 * @param {string} label - Normalized field label
 * @param {string} selectedKey - FIELD_MAP key
 */
const saveSiteMapping = async (domain, label, selectedKey) => {
  const mappings = await getSiteMappings();
  
  if (!mappings[domain]) {
    mappings[domain] = {};
  }
  
  mappings[domain][label] = selectedKey;
  
  await chrome.storage.local.set({ siteMappings: mappings });
};

/**
 * Clear all mappings for a domain
 * @param {string} domain - Domain name
 */
const clearSiteMemory = async (domain) => {
  const mappings = await getSiteMappings();
  delete mappings[domain];
  await chrome.storage.local.set({ siteMappings: mappings });
};

/**
 * Normalize label text for consistent storage
 * @param {string} text - Label text
 * @returns {string} Normalized text
 */
const normalizeLabel = (text) => {
  return text.toLowerCase().trim();
};


/**
 * Token Storage Functions
 */

/**
 * Save extension API key via background script (secure storage)
 * The background script handles: store key → authenticate → store JWT
 * @param {string} apiKey - Extension secret key
 * @returns {Promise<Object>} Result from background
 */
const saveApiKey = (apiKey) => {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'SAVE_API_KEY', apiKey }, resolve);
  });
};

/**
 * Retrieve authentication token from chrome.storage.local
 * @returns {Promise<string|null>} The stored token or null
 */
const getToken = async () => {
  try {
    const result = await chrome.storage.local.get(['jwtToken']);
    return result.jwtToken || null;
  } catch (error) {
    console.error('[Popup] Error retrieving token:', error);
    return null;
  }
};

/**
 * Fetch user profile via background service worker (secure proxy).
 * The JWT never leaves chrome.storage.local — background.js handles
 * the Authorization header internally. Token is NEVER in popup context.
 * @returns {Promise<Object>} User profile data
 */
const fetchProfile = () => {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'FETCH_PROFILE' }, (res) => {
      if (chrome.runtime.lastError) {
        return reject(new Error(chrome.runtime.lastError.message));
      }
      if (res && res.success) {
        // Background returns { success, data: { profile, email } }
        return resolve(res.data.profile);
      }
      const msg = (res && res.message) || 'Failed to fetch profile.';
      if (res && res.code === 'UNAUTHORIZED') {
        return reject(new Error('Session expired. Please login again.'));
      }
      reject(new Error(msg));
    });
  });
};

/**
 * Check login status and update UI
 */
const checkLoginStatus = async () => {
  const token = await getToken();
  const logoutBtn = document.getElementById('logoutBtn');
  const authDetail = document.getElementById('authDetail');

  if (token) {
    statusDot.className = 'status-dot logged-in';
    statusText.textContent = 'Connected';
    logoutBtn.style.display = 'block';
    authDetail.textContent = '';
  } else {
    statusDot.className = 'status-dot logged-out';
    statusText.textContent = 'Not Connected';
    logoutBtn.style.display = 'none';
    authDetail.textContent = '';
  }
};

/**
 * Update login status (wrapper for checkLoginStatus)
 */
const updateLoginStatus = () => {
  checkLoginStatus();
};

/**
 * Inject content script into the active tab if not already present.
 * The manifest auto-injects on Google Forms; for other pages we use
 * the scripting API with activeTab permission (user-initiated click).
 * @param {number} tabId - Tab to inject into
 */
const ensureContentScript = async (tabId) => {
  try {
    // Ping the content script — if it responds, injection is unnecessary
    await chrome.tabs.sendMessage(tabId, { action: 'PING' });
  } catch {
    // Content script not loaded — inject it now (requires activeTab)
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js'],
    });
  }
};

/**
 * Scan Page Button Handler
 */
const handleScanPage = async () => {
  
  try {
    // Disable button during scan
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      showToast('No active tab found', 'error');
      return;
    }

    // Inject content script if needed (non-Google-Forms pages)
    await ensureContentScript(tab.id);
    
    const response = await chrome.tabs.sendMessage(tab.id, { action: 'SCAN_PAGE' });
    
    if (response && response.success) {
      displayResults(response);
    } else {
      showToast('Failed to scan page', 'error');
    }
    
  } catch (error) {
    console.error('[Popup] Error scanning page:', error);
    showToast('Make sure you\'re on a valid web page', 'error');
  } finally {
    // Re-enable button
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span class="btn-icon">🔍</span> Scan Page';
  }
};

/**
 * Save API Key Button Handler
 */
const handleSaveToken = async () => {
  const key = tokenInput.value.trim();
  
  if (!key) {
    showToast('Please paste your secret key', 'warn');
    return;
  }

  // Soft-launch keys use fillr_XXXXXX-XXXXXX-XXXXXX format (~25 chars)
  if (key.length < 10) {
    showToast('Invalid key format', 'error');
    return;
  }
  
  try {
    saveTokenBtn.disabled = true;
    saveTokenBtn.textContent = 'Connecting...';

    const result = await saveApiKey(key);
    
    if (result && result.success) {
      tokenInput.value = '';
      showToast('✅ Connected successfully!', 'success');
      updateLoginStatus();
    } else {
      showToast(result?.message || 'Invalid or expired key', 'error');
    }
  } catch (error) {
    showToast('Failed to connect', 'error');
  } finally {
    saveTokenBtn.disabled = false;
    saveTokenBtn.textContent = 'Connect';
  }
};

/**
 * Display medium-confidence fields in popup UI.
 * Shows: Label | Suggested Value | Mapping Dropdown | Apply Button per field.
 * @param {Array} confirmations - Array of medium-confidence field objects
 */
const displayConfirmations = async (confirmations) => {
  if (!confirmations || confirmations.length === 0) {
    confirmationsSection.style.display = 'none';
    updatePendingBanner(0);
    return;
  }
  
  // Store globally for later use
  pendingConfirmationsData = confirmations;
  
  const map = await ensureFieldMap();
  const allKeys = Object.keys(map).sort((a, b) => a.localeCompare(b));

  confirmationsContent.innerHTML = '';
  
  confirmations.forEach((conf) => {
    const selectedKey = conf.suggestedKey;
    const selectedValue = resolveProfileValueForKey(selectedKey) || conf.suggestedValue || '';
    const optionKeys = allKeys.length > 0 ? allKeys : [selectedKey];
    const optionsHtml = optionKeys.map((key) => `
      <option value="${esc(key)}" ${key === selectedKey ? 'selected' : ''}>${esc(key)}</option>
    `).join('');

    const confItem = document.createElement('div');
    confItem.className = 'confirmation-item';
    confItem.setAttribute('data-field-id', conf.fieldId);
    confItem.innerHTML = `
      <div class="confirmation-field">
        <div class="confirmation-label-row">
          <label class="confirmation-label">
            <strong>${esc(conf.labelText)}</strong>
            <span class="confidence-badge">${(conf.confidence * 100).toFixed(0)}%</span>
          </label>
        </div>
        <select class="confirmation-select" data-field-id="${conf.fieldId}">
          ${optionsHtml}
        </select>
        <div class="confirmation-value-row">
          <span class="suggested-value">${esc(selectedValue || '\u2014')}</span>
          <button class="btn-apply-field btn btn-blue btn-xs"
                  data-field-id="${conf.fieldId}"
                  data-match-key="${esc(selectedKey)}">
            Apply
          </button>
        </div>
      </div>
    `;
    confirmationsContent.appendChild(confItem);
  });
  
  // Add event listeners for mapping dropdown changes
  confirmationsContent.querySelectorAll('.confirmation-select').forEach(select => {
    select.addEventListener('change', (event) => {
      const selected = event.target;
      const item = selected.closest('.confirmation-item');
      const applyBtn = item?.querySelector('.btn-apply-field');
      const valueEl = item?.querySelector('.suggested-value');

      if (!applyBtn || !valueEl) return;

      applyBtn.dataset.matchKey = selected.value;
      const resolved = resolveProfileValueForKey(selected.value);
      valueEl.textContent = resolved || '\u2014';
    });
  });

  // Add event listeners for individual Apply buttons
  confirmationsContent.querySelectorAll('.btn-apply-field').forEach(btn => {
    btn.addEventListener('click', () => applyMediumField(btn));
  });
  
  confirmationsSection.style.display = 'block';
  updatePendingBanner(confirmations.length);
};

/**
 * Apply a single medium-confidence field by sending message to content script
 * @param {HTMLButtonElement} btn - The Apply button that was clicked
 */
const applyMediumField = async (btn) => {
  const fieldId = btn.dataset.fieldId;
  const selectedKey = btn.dataset.matchKey;
  const conf = pendingConfirmationsData.find(c => c.fieldId === fieldId);
  if (!conf) return;

  const valueToApply = resolveProfileValueForKey(selectedKey) || conf.suggestedValue;

  if (!selectedKey || !valueToApply) {
    showToast('No profile value found for selected mapping', 'warn');
    return;
  }
  
  try {
    btn.disabled = true;
    btn.textContent = 'Applying\u2026';
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const response = await chrome.tabs.sendMessage(tab.id, {
      action: 'APPLY_MEDIUM_FILL',
      fieldId: fieldId,
      matchKey: selectedKey,
      value: valueToApply
    });
    
    if (response && response.success) {
      btn.textContent = '\u2713 Applied';
      btn.disabled = true;
      const item = btn.closest('.confirmation-item');
      if (item) item.style.opacity = '0.5';
      
      // Save learned mapping for this domain
      const domain = await getCurrentDomain();
      if (domain) {
        const label = normalizeLabel(conf.labelText);
        saveSiteMapping(domain, label, selectedKey);
      }
      
      // Remove from pending list
      pendingConfirmationsData = pendingConfirmationsData.filter(c => c.fieldId !== fieldId);
      updatePendingBanner(pendingConfirmationsData.length);
      
      showToast(`Applied: ${conf.labelText}`, 'success', 2000);
      displayLearnedMappings();
    } else {
      btn.textContent = 'Failed';
      showToast('Failed to apply field', 'error');
      setTimeout(() => { btn.textContent = 'Apply'; btn.disabled = false; }, 2000);
    }
  } catch (err) {
    console.error('[Popup] Error applying medium field:', err);
    btn.textContent = 'Error';
    showToast('Error applying field', 'error');
    setTimeout(() => { btn.textContent = 'Apply'; btn.disabled = false; }, 2000);
  }
};



/**
 * Autofill Page Button Handler
 */
const handleAutofillPage = async () => {
  
  try {
    // Disable button during autofill
    autofillBtn.disabled = true;
    autofillBtn.textContent = 'Autofilling...';
    
    // Check if user is logged in
    const token = await getToken();
    
    if (!token) {
      showToast('Please connect first', 'warn');
      return;
    }
    
    // Fetch profile via background proxy — token never enters popup context
    const profileData = await fetchProfile();
    currentProfile = profileData;
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      showToast('No active tab found', 'error');
      return;
    }

    // Inject content script if needed (non-Google-Forms pages)
    await ensureContentScript(tab.id);
    
    // Get current domain and learned mappings
    const domain = await getCurrentDomain();
    const allMappings = await getSiteMappings();
    const siteMappings = allMappings[domain] || {};
    
    const response = await chrome.tabs.sendMessage(tab.id, {
      action: 'AUTOFILL_PAGE',
      profile: profileData,
      domain: domain,
      siteMappings: siteMappings
    });
    
    if (response && response.status === 'config_unavailable') {
      showToast('Configuration unavailable.', 'error', 2200);
      confirmationsSection.style.display = 'none';
      updatePendingBanner(0);
      pendingConfirmationsData = [];
      return;
    }

    if (response && response.status === 'completed') {
      const { autoFilledCount, pendingConfirmations } = response;
      
      // Display medium-confidence fields for review in popup
      if (pendingConfirmations && pendingConfirmations.length > 0) {
        displayConfirmations(pendingConfirmations);
      }
      
      // Show success toast
      if (pendingConfirmations && pendingConfirmations.length > 0) {
        showToast(`✅ Filled ${autoFilledCount} | ${pendingConfirmations.length} need review ↓`, 'warn', 4000);
      } else {
        showToast(`✅ Autofilled ${autoFilledCount} field(s)!`, 'success');
      }
    } else if (response && response.status !== 'error') {
      console.error('[Popup] Unexpected response from content script:', response);
      showToast('Failed to autofill page', 'error');
    } else {
      showToast(response?.error || 'Autofill error', 'error');
    }
    
  } catch (error) {
    console.error('[Popup] Error autofilling page:', error);
    
    if (error.message.includes('Session expired')) {
      showToast('Session expired. Reconnect please.', 'error');
    } else {
      showToast('Please refresh the page and try again.', 'error', 4000);
    }
  } finally {
    // Re-enable button
    autofillBtn.disabled = false;
    autofillBtn.innerHTML = '<span class="btn-icon">✨</span> Autofill Page';
  }
};

/**
 * Display scan results in popup
 * @param {Object} response - Response from content script
 */
const displayResults = (response) => {
  const { fields, url, title } = response;
  
  // Show results section
  resultsSection.style.display = 'block';
  
  // Build results HTML — all external text escaped to prevent XSS
  let html = `
    <div class="result-header">
      <p><strong>Page:</strong> ${esc(title)}</p>
      <p><strong>Fields Found:</strong> ${fields.length}</p>
    </div>
    <div class="fields-list">
  `;
  
  if (fields.length === 0) {
    html += '<p class="no-fields">No form fields detected on this page.</p>';
  } else {
    fields.forEach((field, index) => {
      html += `
        <div class="field-item">
          <div class="field-number">#${index + 1}</div>
          <div class="field-details">
            ${field.label ? `<p><strong>Label:</strong> ${esc(field.label)}</p>` : ''}
            ${field.placeholder ? `<p><strong>Placeholder:</strong> ${esc(field.placeholder)}</p>` : ''}
            ${field.name ? `<p><strong>Name:</strong> ${esc(field.name)}</p>` : ''}
            ${field.id ? `<p><strong>ID:</strong> ${esc(field.id)}</p>` : ''}
            <p><strong>Type:</strong> ${esc(field.type)}</p>
          </div>
        </div>
      `;
    });
  }
  
  html += '</div>';
  resultsContent.innerHTML = html;
};

/**
 * Display learned mappings for the current site
 */
const displayLearnedMappings = async () => {
  const domain = await getCurrentDomain();
  const mappings = await getSiteMappings();
  const siteMappings = mappings[domain] || {};
  
  const learnedSection = document.getElementById('learnedSection');
  const learnedContent = document.getElementById('learnedContent');
  
  const entries = Object.entries(siteMappings);
  
  if (entries.length === 0) {
    learnedSection.style.display = 'none';
    return;
  }
  
  learnedContent.innerHTML = entries.map(([label, key]) => `
    <div class="learned-item">
      <span class="learned-label">${esc(label)}</span>
      <span class="learned-arrow">→</span>
      <span class="learned-key">${esc(key)}</span>
    </div>
  `).join('');
  
  learnedSection.style.display = 'block';
};

/**
 * Handle Clear Memory Button Click
 */
const handleClearMemory = async () => {
  const domain = await getCurrentDomain();
  
  if (!domain) {
    showToast('Cannot determine domain', 'error');
    return;
  }
  
  if (confirm(`Clear learned mappings for ${domain}?`)) {
    await clearSiteMemory(domain);
    displayLearnedMappings();
    showToast('Memory cleared', 'success');
  }
};

/**
 * Handle logout / disconnect
 */
const handleLogout = () => {
  if (!confirm('Disconnect extension?')) return;
  chrome.runtime.sendMessage({ type: 'CLEAR_TOKEN' }, () => {
    updateLoginStatus();
    showToast('Disconnected', 'success');
  });
};

/**
 * Scroll to pending confirmations section
 */
const scrollToConfirmations = () => {
  confirmationsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

/**
 * Initialize popup
 */
const init = () => {
  
  // Check login status on load
  checkLoginStatus();
  
  // Display learned mappings for current site
  displayLearnedMappings();
  
  // Add event listeners
  scanBtn.addEventListener('click', handleScanPage);
  autofillBtn.addEventListener('click', handleAutofillPage);
  saveTokenBtn.addEventListener('click', handleSaveToken);
  document.getElementById('clearMemoryBtn').addEventListener('click', handleClearMemory);
  document.getElementById('logoutBtn').addEventListener('click', handleLogout);
  document.getElementById('showAllFieldsBtn').addEventListener('click', highlightAllPendingFields);
  document.getElementById('pendingBanner').addEventListener('click', scrollToConfirmations);
  
  // Listen for medium-confidence results sent proactively from content script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'MEDIUM_CONFIDENCE_RESULTS') {
      displayConfirmations(message.fields);
      sendResponse({ received: true });
    }
  });
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
