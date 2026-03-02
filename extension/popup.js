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
const applyConfirmationsBtn = document.getElementById('applyConfirmationsBtn');

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
 * Display pending confirmations in UI
 * @param {Array} confirmations - Array of pending confirmation objects
 * @param {Object} profile - User profile for reference
 */
const displayConfirmations = (confirmations, profile) => {
  if (!confirmations || confirmations.length === 0) {
    confirmationsSection.style.display = 'none';
    updatePendingBanner(0);
    return;
  }
  
  // Store globally for later use
  pendingConfirmationsData = confirmations;
  currentProfile = profile;
  
  // Get all available field keys from FIELD_MAP (we'll need to import this or hardcode)
  const fieldKeys = [
    'name', 'email', 'phone', 'gender', 'dob', 'age', 'permanent_address',
    'tenth_percentage', 'twelfth_percentage', 'diploma_percentage', 'graduation_percentage', 'pg_percentage', 'cgpa',
    'active_backlog', 'backlog_count', 'gap_months',
    'uid', 'university_roll_number', 
    'college_name', 'batch', 'program', 'stream',
    'position_applying',
    'github', 'linkedin', 'portfolio'
  ];
  
  confirmationsContent.innerHTML = '';
  
  confirmations.forEach((conf, index) => {
    const confItem = document.createElement('div');
    confItem.className = 'confirmation-item';
    confItem.innerHTML = `
      <div class="confirmation-field">
        <div class="confirmation-label-row">
          <label class="confirmation-label">
            <strong>${esc(conf.labelText)}</strong>
            <span class="confidence-badge">${(conf.confidence * 100).toFixed(0)}%</span>
          </label>
          <button class="btn-show-field" data-field-id="${conf.fieldId}" title="Scroll to this field">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            Show
          </button>
        </div>
        <select class="confirmation-select" data-field-id="${conf.fieldId}">
          <option value="">-- Skip this field --</option>
          ${fieldKeys.map(key => `
            <option value="${key}" ${key === conf.suggestedKey ? 'selected' : ''}>
              ${key} ${key === conf.suggestedKey ? '(suggested)' : ''}
            </option>
          `).join('')}
        </select>
      </div>
    `;
    confirmationsContent.appendChild(confItem);
  });
  
  // Add event listeners for show buttons
  confirmationsContent.querySelectorAll('.btn-show-field').forEach(btn => {
    btn.addEventListener('click', () => highlightFieldOnPage(btn.dataset.fieldId));
  });
  
  confirmationsSection.style.display = 'block';
  
  // Show banner to notify user about pending confirmations
  updatePendingBanner(confirmations.length);
};

/**
 * Handle Apply Confirmations Button Click
 */
const handleApplyConfirmations = async () => {
  
  try {
    applyConfirmationsBtn.disabled = true;
    applyConfirmationsBtn.textContent = 'Applying...';
    
    // Collect user selections
    const confirmations = [];
    const selects = confirmationsContent.querySelectorAll('.confirmation-select');
    
    // Get current domain for saving learned mappings
    const domain = await getCurrentDomain();
    
    selects.forEach(select => {
      const fieldId = select.getAttribute('data-field-id');
      const selectedKey = select.value;
      
      if (selectedKey) {
        // Find the original confirmation to get labelText
        const conf = pendingConfirmationsData.find(c => c.fieldId === fieldId);
        
        if (conf && domain) {
          const normalizedLabel = normalizeLabel(conf.labelText);
          // Save learned mapping for this domain
          saveSiteMapping(domain, normalizedLabel, selectedKey);
        }
        
        confirmations.push({
          fieldId,
          selectedKey,
          profile: currentProfile
        });
      }
    });
    
    if (confirmations.length === 0) {
      showToast('No fields selected', 'warn');
      return;
    }
    
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    const response = await chrome.tabs.sendMessage(tab.id, {
      action: 'CONFIRM_AUTOFILL',
      confirmations: confirmations
    });
    
    if (response && response.status === 'confirmed') {
      showToast(`✅ Confirmed ${response.confirmedCount} field(s)!`, 'success');
      confirmationsSection.style.display = 'none';
      updatePendingBanner(0);
      pendingConfirmationsData = [];
      // Refresh learned mappings display
      displayLearnedMappings();
    }
    
  } catch (error) {
    console.error('[Popup] Error applying confirmations:', error);
    showToast(error.message, 'error');
  } finally {
    applyConfirmationsBtn.disabled = false;
    applyConfirmationsBtn.textContent = 'Apply Confirmed Autofill';
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

    if (response && response.status === 'cancelled') {
      showToast('Autofill cancelled', 'warn', 1800);
      confirmationsSection.style.display = 'none';
      updatePendingBanner(0);
      pendingConfirmationsData = [];
      return;
    }

    if (response && response.status === 'completed') {
      const { autoFilledCount, pendingConfirmations, filledFields, skippedFields } = response;
      
      // Display pending confirmations if any
      if (pendingConfirmations && pendingConfirmations.length > 0) {
        displayConfirmations(pendingConfirmations, profileData);
      }
      
      // Show success toast
      if (pendingConfirmations && pendingConfirmations.length > 0) {
        showToast(`✅ Filled ${autoFilledCount} | ${pendingConfirmations.length} need review ↓`, 'warn', 4000);
      } else {
        showToast(`✅ Autofilled ${autoFilledCount} field(s)!`, 'success');
      }
    } else {
      console.error('[Popup] Invalid response from content script');
      showToast('Failed to autofill page', 'error');
    }
    
  } catch (error) {
    console.error('[Popup] Error autofilling page:', error);
    
    if (error.message.includes('Session expired')) {
      showToast('Session expired. Reconnect please.', 'error');
    } else {
      showToast('Server unreachable', 'error');
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
  applyConfirmationsBtn.addEventListener('click', handleApplyConfirmations);
  document.getElementById('clearMemoryBtn').addEventListener('click', handleClearMemory);
  document.getElementById('logoutBtn').addEventListener('click', handleLogout);
  document.getElementById('showAllFieldsBtn').addEventListener('click', highlightAllPendingFields);
  document.getElementById('pendingBanner').addEventListener('click', scrollToConfirmations);
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
