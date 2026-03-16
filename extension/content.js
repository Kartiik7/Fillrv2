/**
 * content.js — Form Field Detection & Autofill Engine
 *
 * Injected into Google Forms pages (via manifest) and on-demand into other
 * pages (via chrome.scripting.executeScript from popup when user clicks
 * Scan/Autofill — requires activeTab permission, user-initiated only).
 *
 * Security architecture:
 *  - No access to JWT or API key — all API communication goes through
 *    background.js service worker. This script receives only sanitized
 *    profile data via chrome.runtime message passing.
 *  - No eval(), no Function(), no remote script loading.
 *  - No innerHTML injection of external data — all DOM writes are via
 *    element.value assignment or click simulation.
 *  - DEBUG flag is hard-coded to false for production. When true, only
 *    field labels and match scores are logged — never profile values.
 *  - UNSAFE_LABELS list prevents filling declaration/consent/upload fields.
 *
 * Attack vector mitigations:
 *  - Malicious page trying to read extension data:
 *      Content scripts run in an isolated world. Page JS cannot access
 *      chrome.runtime or chrome.storage APIs. The only bridge is the
 *      message listener below, which only responds to messages from the
 *      extension's own runtime (not from page scripts).
 *  - Content script injection abuse:
 *      Content script is only auto-injected on docs.google.com/forms/*.
 *      On other pages, injection requires user click (activeTab).
 *  - XSS via autofilled values:
 *      Values are set via element.value (not innerHTML). This is a safe
 *      DOM property assignment that cannot execute scripts.
 *  - DOM clobbering:
 *      Element registry uses a private Map(), not global DOM ids.
 */

/**
 * Element Registry - Stable in-memory storage for detected form elements
 * Maps fieldId -> HTMLElement to avoid fragile CSS selector lookups
 */
const elementRegistry = new Map();

// Global debug flag and logger
// Set DEBUG = true only during local development — never in production releases.
// Protects against: PII (name, phone, DOB etc.) appearing in DevTools console
// which could be read by browser extensions or observed during screen sharing.
const DEBUG = false;
const DIAG = false; // Enable temporarily for manual diagnostics only
const log = (...args) => {
  if (DEBUG) console.log("FILLR DEBUG:", ...args);
};
const diag = (...args) => {
  if (DEBUG || DIAG) console.log("FILLR DIAG:", ...args);
};

// Google Forms detection flag
const isGoogleForm = window.location.hostname.includes("docs.google.com");

// MATCH_CONFIDENCE_THRESHOLD, HIGH_CONFIDENCE, MEDIUM_CONFIDENCE,
// normalizeOption, normalizeLabel, calculateOptionScore, tokenize,
// calculateAdvancedScore, hasNumericAnchor, preprocessConfig, preprocessMappings
// are defined in matcher.js (loaded before this script via manifest.json).
//
// Background message types used by this script:
//   FETCH_FULL_CONFIG  — fetches { version, mappings } in one round trip
//   FETCH_PROFILE      — fetches user profile (autofill trigger)
//   SAVE_LEARNED_MAPPING, GET_LEARNED_MAPPING — site-specific learned fills

// Labels that should never be autofilled (safety)
const UNSAFE_LABELS = [
  "undertaking",
  "declaration",
  "agreement",
  "send me a copy",
  "file upload",
  "upload",
  "attach",
  "signature",
  "i agree",
  "terms and conditions",
];

/**
 * Check if a field label is unsafe to autofill
 * @param {string} label - The label text
 * @returns {boolean} True if the label indicates an unsafe field
 */
const isUnsafeLabel = (label) => {
  if (!label) return false;
  const normalized = label.toLowerCase();
  return UNSAFE_LABELS.some((unsafe) => normalized.includes(unsafe));
};

/**
 * Detects all form fields on the current page
 * @returns {Array} Array of field metadata objects
 */
const detectFormFields = () => {
  // Clear registry to prevent stale references
  elementRegistry.clear();

  const fields = [];
  const selectors = ["input", "textarea", "select"];

  selectors.forEach((selector) => {
    const elements = document.querySelectorAll(selector);

    elements.forEach((element, index) => {
      // Skip hidden fields and buttons
      if (
        element.type === "hidden" ||
        element.type === "submit" ||
        element.type === "button"
      ) {
        return;
      }

      const fieldData = {
        label: getFieldLabel(element),
        placeholder: (element.placeholder || "").toLowerCase().trim(),
        name: (element.name || "").toLowerCase().trim(),
        id: (element.id || "").toLowerCase().trim(),
        type: element.type || element.tagName.toLowerCase(),
        tagName: element.tagName.toLowerCase(),
      };

      fields.push(fieldData);
    });
  });

  // Google Forms: Detect custom dropdown and radio elements
  if (isGoogleForm) {
    const googleDropdowns = document.querySelectorAll('[role="listbox"]');
    googleDropdowns.forEach((element) => {
      const container = element.closest('[role="listitem"]');
      const heading = container?.querySelector('[role="heading"]');
      const labelText = heading?.innerText || "";
      fields.push({
        label: labelText.toLowerCase().trim(),
        placeholder: "",
        name: "",
        id: "",
        type: "google-dropdown",
        tagName: "div",
      });
    });

    const googleRadios = document.querySelectorAll('[role="radio"]');
    const processedContainers = new Set();
    googleRadios.forEach((element) => {
      const container = element.closest('[role="listitem"]');
      if (container && !processedContainers.has(container)) {
        processedContainers.add(container);
        const heading = container.querySelector('[role="heading"]');
        const labelText = heading?.innerText || "";
        fields.push({
          label: labelText.toLowerCase().trim(),
          placeholder: "",
          name: "",
          id: "",
          type: "google-radio",
          tagName: "div",
        });
      }
    });
  }

  return fields;
};

/**
 * Attempts to find and extract label text for a form field (Google Forms compatible)
 * @param {HTMLElement} element - The form field element
 * @returns {string} Normalized label text
 */
const getFieldLabel = (element) => {
  let labelText = "";

  // Method 1: Check for aria-label attribute (Google Forms uses this heavily)
  if (element.getAttribute("aria-label")) {
    labelText = element.getAttribute("aria-label");
    return labelText.toLowerCase().trim();
  }

  // Method 2: Check for Google Forms question container heading
  const questionContainer = element.closest('[role="listitem"]');
  if (questionContainer) {
    const heading = questionContainer.querySelector('[role="heading"]');
    if (heading) {
      labelText = heading.innerText;
      return labelText.toLowerCase().trim();
    }
  }

  // Method 3: Check for <label> with matching 'for' attribute
  if (element.id) {
    const label = document.querySelector(`label[for="${element.id}"]`);
    if (label) {
      labelText = label.textContent;
      return labelText.toLowerCase().trim();
    }
  }

  // Method 4: Radio Button Special Handling (Traverse up for Group Label)
  if (element.type === "radio") {
    // Look for a fieldset legend
    const fieldset = element.closest("fieldset");
    if (fieldset) {
      const legend = fieldset.querySelector("legend");
      if (legend) return legend.innerText.toLowerCase().trim();
    }

    // Look for a container with a preceding label (Common in Bootstrap/Custom forms)
    // Traverse up to 3 levels to find a container that has a previous sibling label
    let parent = element.parentElement;
    for (let i = 0; i < 3; i++) {
      if (!parent) break;

      // Check previous sibling of this parent
      let sibling = parent.previousElementSibling;
      if (
        sibling &&
        (sibling.tagName === "LABEL" ||
          sibling.classList.contains("label") ||
          sibling.tagName === "H3" ||
          sibling.tagName === "H4")
      ) {
        return sibling.innerText.toLowerCase().trim();
      }

      // Check if parent has a label inside it but before the container that wraps radios
      // (e.g. <div class="form-group"><label>Question</label><div><radio>...</div></div>)
      const internalLabel = parent.querySelector("label");
      if (
        internalLabel &&
        !internalLabel.contains(element) &&
        internalLabel.innerText.trim().length > 0
      ) {
        // Verify this label is "before" the element in document order
        if (
          internalLabel.compareDocumentPosition(element) &
          Node.DOCUMENT_POSITION_FOLLOWING
        ) {
          return internalLabel.innerText.toLowerCase().trim();
        }
      }

      parent = parent.parentElement;
    }
  }

  // Method 5: Check if element is wrapped in a <label> (Legacy fallback)
  // Only use this if it's NOT a radio, or if we failed to find a group label
  if (!labelText) {
    const parentLabel = element.closest("label");
    if (parentLabel) {
      labelText = parentLabel.textContent;
      // If it's a radio, this might just be the option text "Male".
      // We accept it as a fallback, but rely on semantic matching to reject "Male" matching "Gender" field map
      return labelText.toLowerCase().trim();
    }
  }

  if (element.type === "radio" && DEBUG) {
    // Intentionally empty — debug logging is gated by DEBUG flag
  }

  // Method 6: Check generic aria-labelledby
  if (!labelText && element.getAttribute("aria-labelledby")) {
    const labelId = element.getAttribute("aria-labelledby");
    const labelElement = document.getElementById(labelId);
    if (labelElement) {
      labelText = labelElement.textContent;
      return labelText.toLowerCase().trim();
    }
  }

  // Method 7: Check previous sibling elements for label-like text (Direct sibling)
  if (!labelText) {
    let sibling = element.previousElementSibling;
    while (sibling && !labelText) {
      if (
        sibling.tagName === "LABEL" ||
        sibling.tagName === "SPAN" ||
        sibling.tagName === "DIV"
      ) {
        const text = sibling.textContent.trim();
        if (text.length > 0 && text.length < 100) {
          labelText = text;
          break;
        }
      }
      sibling = sibling.previousElementSibling;
    }
  }

  return labelText.toLowerCase().trim();
};

/**
 * Get the individual option label for a radio button
 * This is different from getFieldLabel which returns the group/question label
 * @param {HTMLInputElement} radioElement - The radio button element
 * @returns {string} The option label text (e.g., "Male", "CSE", "2026")
 */
const getRadioOptionLabel = (radioElement) => {
  // Method 1: Check if radio is wrapped in a label
  const parentLabel = radioElement.closest("label");
  if (parentLabel) {
    // Get text content but exclude the radio input itself
    const clone = parentLabel.cloneNode(true);
    const inputs = clone.querySelectorAll("input");
    inputs.forEach((inp) => inp.remove());
    const text = clone.textContent.trim();
    if (text) return text.toLowerCase();
  }

  // Method 2: Check for label with matching 'for' attribute
  if (radioElement.id) {
    const label = document.querySelector(`label[for="${radioElement.id}"]`);
    if (label) {
      return label.textContent.toLowerCase().trim();
    }
  }

  // Method 3: Check next sibling (common pattern: <input type="radio"> <span>Option</span>)
  let sibling = radioElement.nextSibling;
  while (sibling) {
    if (sibling.nodeType === Node.TEXT_NODE && sibling.textContent.trim()) {
      return sibling.textContent.toLowerCase().trim();
    }
    if (sibling.nodeType === Node.ELEMENT_NODE && sibling.textContent.trim()) {
      return sibling.textContent.toLowerCase().trim();
    }
    sibling = sibling.nextSibling;
  }

  // Method 4: Fall back to value attribute
  return (radioElement.value || "").toLowerCase().trim();
};

/**
 * Get all radio buttons in the same group
 * @param {HTMLInputElement} radioElement
 * @returns {HTMLInputElement[]}
 */
const getRadioGroup = (radioElement) => {
  const name = radioElement.name;
  if (!name) return [radioElement];
  return Array.from(
    document.querySelectorAll(`input[type="radio"][name="${name}"]`),
  );
};

/**
 * Helper to physically select/check an option
 * @param {HTMLElement} option - Conceptually an option (Option element or Radio Input)
 */
const selectOption = (option) => {
  if (option.tagName === "OPTION") {
    const select = option.closest("select");
    if (select) {
      select.value = option.value;
      select.dispatchEvent(new Event("change", { bubbles: true }));
      select.dispatchEvent(new Event("input", { bubbles: true }));
    }
  } else if (option.type === "radio") {
    if (!option.checked) {
      option.click();
      if (!option.checked) {
        option.checked = true;
        option.dispatchEvent(new Event("change", { bubbles: true }));
        option.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
  }
};

// Simple semantic matcher for dropdowns (bi-directional contains)
const semanticMatch = (profileValue, optionText) => {
  const p = String(profileValue || '').toLowerCase().trim();
  const o = String(optionText || '').toLowerCase().trim();
  if (!p || !o) return false;
  return o.includes(p) || p.includes(o);
};

const waitForOptionsToRender = (ms = 300) =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Fill a Google Forms dropdown using click simulation (no .value assignment)
 * Handles elements with role="listbox" or aria-haspopup="listbox".
 * @param {HTMLElement} element - The listbox element
 * @param {string} profileValue - Value from profile to match
 * @returns {Promise<boolean>} True if option was selected
 */
async function fillGoogleDropdown(element, profileValue) {
  element.click();

  await waitForOptionsToRender();

  const options = document.querySelectorAll('[role="option"]');

  for (const option of options) {
    const text = option.innerText.toLowerCase().trim();

    if (semanticMatch(profileValue, text)) {
      option.click();
      return true;
    }
  }

  return false;
}

/**
 * Extract the label text from a Google Forms radio option
 * Google Forms has complex DOM structure where the visible text might be in various places
 * @param {HTMLElement} radio - The role="radio" element
 * @returns {string} The option label text
 */
const getGoogleRadioOptionText = (radio) => {
  // Method 1: Check data-value attribute (Google Forms sometimes uses this)
  if (radio.dataset?.value) {
    return radio.dataset.value;
  }
  
  // Method 2: Check aria-label (most reliable for Google Forms)
  if (radio.getAttribute('aria-label')) {
    return radio.getAttribute('aria-label');
  }
  
  // Method 3: Check data-answer-value (Google Forms uses this)
  if (radio.getAttribute('data-answer-value')) {
    return radio.getAttribute('data-answer-value');
  }

  // Method 4: Look for span with dir="auto" (Google Forms option text pattern)
  const spanWithDir = radio.querySelector('span[dir="auto"]');
  if (spanWithDir?.innerText?.trim()) {
    return spanWithDir.innerText.trim();
  }
  
  // Method 5: Look for innerText directly on the radio element
  // Google Forms often has the text directly inside the clickable div
  const directText = radio.innerText?.trim();
  if (directText && directText.length > 0 && directText.length < 100) {
    return directText;
  }

  // Method 6: Look for any span with text inside the radio
  const spans = radio.querySelectorAll('span');
  for (const span of spans) {
    const text = span.innerText?.trim();
    if (text && text.length > 0 && text.length < 100) {
      return text;
    }
  }
  
  // Method 7: Check next sibling for label text (common pattern)
  const nextSibling = radio.nextElementSibling;
  if (nextSibling) {
    const siblingText = nextSibling.innerText?.trim();
    if (siblingText && siblingText.length < 100) return siblingText;
  }
  
  // Method 8: Check parent's direct child text nodes and spans
  const parent = radio.parentElement;
  if (parent) {
    // Look for sibling spans/divs with text
    for (const child of parent.children) {
      if (child !== radio && child.innerText?.trim()) {
        const text = child.innerText.trim();
        if (text.length > 0 && text.length < 100) return text;
      }
    }
    
    // Look for content description
    const contentDesc = parent.querySelector('[data-value]');
    if (contentDesc?.getAttribute('data-value')) {
      return contentDesc.getAttribute('data-value');
    }
  }

  // Method 9: Walk up to find the option container and extract text
  // Google Forms wraps each option in a container div
  let optionContainer = radio.closest('[data-value]');
  if (optionContainer?.getAttribute('data-value')) {
    return optionContainer.getAttribute('data-value');
  }
  
  // Method 10: Last resort - clone parent, remove radio, get remaining text
  if (parent) {
    const clone = parent.cloneNode(true);
    const radioInClone = clone.querySelector('[role="radio"]');
    if (radioInClone) radioInClone.remove();
    const remainingText = clone.innerText?.trim();
    if (remainingText && remainingText.length < 100) return remainingText;
  }
  
  if (DEBUG) log(`Radio text extraction failed for:`, radio.outerHTML?.substring(0, 200));
  return '';
}

/**
 * Fill a Google Forms radio group using click simulation
 * @param {string} profileValue - Value from profile to match
 * @param {HTMLElement} [container] - Optional container to scope radio search
 * @returns {boolean} True if a radio was clicked
 */
function fillGoogleRadio(profileValue, container = null) {
  const normalizedProfile = normalizeOption(profileValue);

  const scope = container || document;
  const radios = scope.querySelectorAll('[role="radio"]');
  let matched = false;

  radios.forEach((radio) => {
    const label = normalizeOption(getGoogleRadioOptionText(radio));

    if (label && label.includes(normalizedProfile)) {
      radio.click();
      matched = true;
    }
  });

  return matched;
}

/**
 * Google Forms dropdown handler with hybrid option matching (alias + semantic)
 * @param {HTMLElement} element - The listbox element
 * @param {string} profileValue - Value from profile
 * @param {Object} fieldConfig - FIELD_MAP config with options aliases
 * @returns {Promise<boolean>} True if option was selected
 */
async function fillGoogleDropdownHybrid(element, profileValue, fieldConfig) {
  const normalizedProfile = normalizeOption(profileValue);

  // Build list of acceptable texts from aliases
  let targetTexts = [normalizedProfile];
  if (fieldConfig?.options) {
    for (const [key, aliases] of Object.entries(fieldConfig.options)) {
      const allVariants = [key, ...aliases];
      if (allVariants.some((v) => normalizeOption(v) === normalizedProfile)) {
        targetTexts = [...new Set(allVariants.map(normalizeOption))];
        break;
      }
    }
  }

  // Click to open dropdown
  element.click();
  await waitForOptionsToRender();

  const options = document.querySelectorAll('[role="option"]');

  for (const option of options) {
    const optionText = option.innerText.toLowerCase().trim();
    if (!optionText) continue;

    // Alias/semantic match
    const aliasHit = targetTexts.some((t) => semanticMatch(t, optionText));
    const semanticHit = semanticMatch(profileValue, optionText);

    if (aliasHit || semanticHit) {
      option.click();
      if (DEBUG) log(`Google Dropdown Match: "${profileValue}" -> "${option.innerText}"`);
      return true;
    }
  }

  if (DEBUG)
    log(`Google Dropdown No Match: "${profileValue}"`);
  return false;
}

/**
 * Google Forms radio handler with hybrid option matching (alias + semantic)
 * @param {string} profileValue - Value from profile
 * @param {Object} fieldConfig - FIELD_MAP config with options aliases
 * @param {HTMLElement} [container] - Container to scope radio search
 * @returns {boolean} True if a radio was clicked
 */
function fillGoogleRadioHybrid(profileValue, fieldConfig, container = null) {
  const normalizedProfile = normalizeOption(profileValue);

  // Build list of acceptable texts from aliases
  let targetTexts = [normalizedProfile];
  if (fieldConfig?.options) {
    for (const [key, aliases] of Object.entries(fieldConfig.options)) {
      const allVariants = [key, ...aliases];
      if (allVariants.some((v) => normalizeOption(v) === normalizedProfile)) {
        targetTexts = [...new Set(allVariants.map(normalizeOption))];
        break;
      }
    }
  }

  const scope = container || document;
  const radios = scope.querySelectorAll('[role="radio"]');

  if (DEBUG) {
    log(`fillGoogleRadioHybrid called:`, {
      profileValue,
      normalizedProfile,
      targetTexts,
      containerTag: container?.tagName,
      containerRole: container?.getAttribute?.('role'),
      radiosFound: radios.length,
    });
    // Log all radio labels for debugging
    for (const r of radios) {
      const labelRaw = getGoogleRadioOptionText(r);
      log(`  Radio option: "${labelRaw}" (normalized: "${normalizeOption(labelRaw)}")`);
    }
  }

  // Helper to check if target matches label (exact or whole word)
  const matchesTarget = (label, target) => {
    if (!target || target.length === 0) return false;
    // Exact match
    if (label === target) return true;
    // Whole word match (target is a complete word in label)
    const wordBoundary = new RegExp(`\\b${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    return wordBoundary.test(label);
  };

  // Layer 1a: Exact match first (highest priority)
  for (const radio of radios) {
    const labelRaw = getGoogleRadioOptionText(radio);
    const label = normalizeOption(labelRaw);
    if (!label || label.length === 0) continue;
    
    for (const target of targetTexts) {
      if (label === target) {
        radio.click();
        if (DEBUG) log(`Google Radio Exact Match: "${profileValue}" -> "${labelRaw}"`);
        return true;
      }
    }
  }

  // Layer 1b: Whole word match (second priority)
  for (const radio of radios) {
    const labelRaw = getGoogleRadioOptionText(radio);
    const label = normalizeOption(labelRaw);
    if (!label || label.length === 0) continue;
    
    for (const target of targetTexts) {
      if (target && target.length > 1 && matchesTarget(label, target)) {
        radio.click();
        if (DEBUG) log(`Google Radio Word Match: "${profileValue}" -> "${labelRaw}"`);
        return true;
      }
    }
  }

  // Layer 2: Semantic fallback (probabilistic)
  let bestRadio = null;
  let bestScore = 0;

  for (const radio of radios) {
    const labelRaw = getGoogleRadioOptionText(radio);
    const label = normalizeOption(labelRaw);
    // Skip empty labels
    if (!label || label.length === 0) continue;
    
    const score = calculateOptionScore(label, normalizedProfile);
    if (score > bestScore) {
      bestScore = score;
      bestRadio = radio;
    }
  }

  // Lower threshold for radios since options are limited and explicit
  const RADIO_MATCH_THRESHOLD = 0.4;
  if (bestRadio && bestScore >= RADIO_MATCH_THRESHOLD) {
    bestRadio.click();
    if (DEBUG)
      log(
        `Google Radio Semantic Match: "${profileValue}" -> "${bestRadio.innerText}" (Score: ${bestScore})`,
      );
    return true;
  }

  if (DEBUG)
    log(`Google Radio No Match: "${profileValue}" (best score: ${bestScore})`);
  return false;
}

/**
 * Deterministically match an option using defined aliases (Layer 1)
 * @param {HTMLElement} element - Select or Radio element
 * @param {string} profileValue - Value from profile
 * @param {Object} fieldConfig - Config from FIELD_MAP
 * @returns {HTMLElement|null} Matching option/radio or null
 */
const tryAliasMatch = (element, profileValue, fieldConfig) => {
  if (!fieldConfig || !fieldConfig.options) return null;

  let targetAliases = [];
  const normalizedProfile = normalizeOption(profileValue);
  const isRadio = element.type === "radio";

  // 1. Find matching concept in options map
  for (const [key, aliases] of Object.entries(fieldConfig.options)) {
    if (normalizeOption(key) === normalizedProfile) {
      targetAliases = [...aliases, key];
      break;
    }
    if (aliases.some((a) => normalizeOption(a) === normalizedProfile)) {
      targetAliases = [...aliases, key];
      break;
    }
  }

  if (targetAliases.length === 0) return null;

  // 2. Find DOM option matching any alias
  const domOptions =
    element.tagName === "SELECT"
      ? Array.from(element.options)
      : getRadioGroup(element);

  for (const option of domOptions) {
    // For radio buttons, use getRadioOptionLabel to get individual option text
    const optionText = normalizeOption(
      isRadio ? getRadioOptionLabel(option) : (option.text || option.value),
    );
    const optionValue = normalizeOption(option.value);

    // Check each alias against this option
    for (const alias of targetAliases) {
      const normalizedAlias = normalizeOption(alias);
      if (
        optionText.includes(normalizedAlias) ||
        optionValue === normalizedAlias
      ) {
        return option;
      }
    }
  }

  return null;
};

/**
 * Semantic fallback using fuzzy matching (Layer 2)
 * @param {HTMLElement} element - Select or Radio element
 * @param {string} profileValue - Value from profile
 * @returns {HTMLElement|null} Best matching option/radio or null
 */
const trySemanticOptionMatch = (element, profileValue) => {
  const normalizedProfile = normalizeOption(profileValue);
  const isYesNo = ["yes", "no"].includes(normalizedProfile);
  const isRadio = element.type === "radio";

  const domOptions =
    element.tagName === "SELECT"
      ? Array.from(element.options)
      : getRadioGroup(element);

  let bestMatch = null;
  let bestScore = 0;

  domOptions.forEach((option) => {
    // Skip select placeholders
    if (
      element.tagName === "SELECT" &&
      option.value === "" &&
      domOptions.length > 1
    )
      return;

    // For radio buttons, use getRadioOptionLabel to get individual option text
    // For select options, use option.text
    const optionText = normalizeOption(
      isRadio ? getRadioOptionLabel(option) : (option.text || option.value),
    );
    const optionValue = normalizeOption(option.value);

    if (DEBUG && isRadio) {
      log(`Radio option: text="${optionText}", value="${optionValue}", profile="${normalizedProfile}"`);
    }

    let score = 0;

    if (isYesNo) {
      // Strict check for Yes/No
      if (
        optionText === normalizedProfile ||
        optionValue === normalizedProfile
      ) {
        score = 1.0;
      }
    } else {
      // Fuzzy check
      const scoreText = calculateOptionScore(optionText, normalizedProfile);
      const scoreValue = calculateOptionScore(optionValue, normalizedProfile);
      score = Math.max(scoreText, scoreValue);
    }

    if (score > bestScore) {
      bestScore = score;
      bestMatch = option;
    }
  });

  if (DEBUG && bestMatch)
    log(
      `Semantic Match: "${profileValue}" matched "${bestMatch.value}" (Score: ${bestScore})`,
    );
  return bestScore >= MATCH_CONFIDENCE_THRESHOLD ? bestMatch : null;
};

/**
 * Fill a form field with a value and dispatch events (Google Forms compatible)
 * Supports Text, Radio, and Select inputs with Semantic Matching
 * @param {HTMLElement} element - The form field element
 * @param {string} value - The value to fill
 * @param {Object} [fieldConfig] - Config for the field (for aliases)
 */
/**
 * Check if a value is numeric (integer or decimal)
 * @param {string} value - Value to check
 * @returns {boolean} True if numeric
 */
const isNumericValue = (value) => {
  if (!value) return false;
  return !isNaN(parseFloat(value)) && isFinite(value);
};

/**
 * Parse a date string in multiple formats to { day, month, year } integers.
 * Accepted formats: DD-MM-YYYY, DD/MM/YYYY, YYYY-MM-DD, YYYY/MM/DD
 * Returns null if the value is not a recognised date format or is invalid.
 *
 * @param {string} value - Raw date string
 * @returns {{ day: number, month: number, year: number } | null}
 */
const parseDateParts = (value) => {
  if (!value || typeof value !== 'string') return null;
  const v = value.trim();

  let day, month, year;

  // YYYY-MM-DD or YYYY/MM/DD
  const isoMatch = v.match(/^(\d{4})[\-\/](\d{1,2})[\-\/](\d{1,2})$/);
  if (isoMatch) {
    year  = parseInt(isoMatch[1], 10);
    month = parseInt(isoMatch[2], 10);
    day   = parseInt(isoMatch[3], 10);
  } else {
    // DD-MM-YYYY or DD/MM/YYYY
    const dmyMatch = v.match(/^(\d{1,2})[\-\/](\d{1,2})[\-\/](\d{4})$/);
    if (dmyMatch) {
      day   = parseInt(dmyMatch[1], 10);
      month = parseInt(dmyMatch[2], 10);
      year  = parseInt(dmyMatch[3], 10);
    } else {
      return null;
    }
  }

  // Basic validation
  if (month < 1 || month > 12 || day < 1 || day > 31 || year < 1900 || year > 2100) {
    return null;
  }
  return { day, month, year };
};

/**
 * Convert a date string to ISO format (YYYY-MM-DD).
 * Returns null if the value cannot be parsed.
 * @param {string} value
 * @returns {string|null}
 */
const toISODate = (value) => {
  const parts = parseDateParts(value);
  if (!parts) return null;
  const dd = String(parts.day).padStart(2, '0');
  const mm = String(parts.month).padStart(2, '0');
  return `${parts.year}-${mm}-${dd}`;
};

/**
 * Convert a date string to DD-MM-YYYY display format.
 * Returns null if the value cannot be parsed.
 * @param {string} value
 * @returns {string|null}
 */
const toDMYDate = (value) => {
  const parts = parseDateParts(value);
  if (!parts) return null;
  const dd = String(parts.day).padStart(2, '0');
  const mm = String(parts.month).padStart(2, '0');
  return `${dd}-${mm}-${parts.year}`;
};

/**
 * Dispatch input, change, and blur events on an element.
 * @param {HTMLElement} el
 */
const dispatchDateEvents = (el) => {
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  el.dispatchEvent(new Event('blur', { bubbles: true }));
};

/**
 * Detect split date inputs (separate day / month / year fields)
 * near the given element and fill each part individually.
 *
 * Heuristic: walk up to the closest form-group / fieldset / parent
 * and look for sibling inputs whose name, id, placeholder, or
 * aria-label match day/month/year patterns.
 *
 * @param {HTMLElement} element - The matched date element
 * @param {{ day: number, month: number, year: number }} parts
 * @returns {boolean} True if split inputs were found and filled
 */
const trySplitDateFill = (element, parts) => {
  // Walk up to a reasonable container (fieldset, form-group, or up to 4 parents)
  let container = element.closest('fieldset') ||
                  element.closest('.form-group') ||
                  element.closest('[role="group"]');
  if (!container) {
    container = element.parentElement;
    for (let i = 0; i < 3 && container?.parentElement; i++) {
      if (container.querySelectorAll('input').length >= 3) break;
      container = container.parentElement;
    }
  }
  if (!container) return false;

  const inputs = container.querySelectorAll('input');
  if (inputs.length < 3) return false;

  const DAY_RE   = /\b(day|dd)\b/i;
  const MONTH_RE = /\b(month|mm)\b/i;
  const YEAR_RE  = /\b(year|yyyy|yy)\b/i;

  const identify = (el) => {
    const haystack = [
      el.name, el.id, el.placeholder,
      el.getAttribute('aria-label'),
    ].filter(Boolean).join(' ');
    if (DAY_RE.test(haystack))   return 'day';
    if (MONTH_RE.test(haystack)) return 'month';
    if (YEAR_RE.test(haystack))  return 'year';
    return null;
  };

  let dayEl = null, monthEl = null, yearEl = null;
  for (const inp of inputs) {
    const role = identify(inp);
    if (role === 'day')   dayEl   = inp;
    if (role === 'month') monthEl = inp;
    if (role === 'year')  yearEl  = inp;
  }

  if (!dayEl || !monthEl || !yearEl) return false;

  let changed = false;

  const fillPart = (el, val) => {
    // Do not overwrite user-entered values
    if (el.value && el.value.trim() !== '') return;
    const prev = el.value;
    el.value = String(val);
    dispatchDateEvents(el);
    if (el.value !== prev) changed = true;
  };

  fillPart(dayEl,   String(parts.day).padStart(2, '0'));
  fillPart(monthEl, String(parts.month).padStart(2, '0'));
  fillPart(yearEl,  String(parts.year));

  return changed;
};

/**
 * Universal date field filler.
 *
 * Accepts date strings in DD-MM-YYYY, DD/MM/YYYY, YYYY-MM-DD, YYYY/MM/DD.
 * Routes to the correct fill strategy based on the DOM element type:
 *   • <input type="date">  → sets ISO (YYYY-MM-DD) value + dispatches events
 *   • text/other inputs    → sets DD-MM-YYYY display value
 *   • split inputs nearby  → fills day / month / year individually
 *
 * Does NOT overwrite fields that already contain user-entered values.
 *
 * @param {HTMLElement} element - The form field element
 * @param {string} value - Raw date string from profile
 * @returns {boolean} True if the value actually changed
 */
const fillDateField = (element, value) => {
  if (!element || !value) return false;

  const parts = parseDateParts(String(value));
  if (!parts) {
    if (DEBUG) log('fillDateField: unparseable date value:', value);
    return false;
  }

  // Do not overwrite user-entered values
  if (element.value && element.value.trim() !== '') return false;

  // Attempt split-input fill first (day / month / year in separate fields)
  if (trySplitDateFill(element, parts)) return true;

  const domType = (element.type || '').toLowerCase();
  const iso = toISODate(value);
  const dmy = toDMYDate(value);
  if (!iso || !dmy) return false;

  const previousValue = element.value;

  if (domType === 'date' || domType === 'datetime-local' || domType === 'month') {
    // HTML5 date inputs require ISO format
    element.value = iso;
    // Use native setter to ensure frameworks (React, Angular) pick up the change
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;
    if (nativeSetter) {
      nativeSetter.call(element, iso);
    }
    dispatchDateEvents(element);
  } else {
    // Normal text input — use DD-MM-YYYY display format
    element.value = dmy;
    dispatchDateEvents(element);
  }

  return element.value !== previousValue && element.value.trim() !== '';
};

/**
 * Format date value for different input types (legacy wrapper).
 * @param {string} value - Date value (could be various formats)
 * @param {string} inputType - The input type (date, text, etc.)
 * @returns {string} Formatted date string
 */
const formatDateValue = (value, inputType) => {
  if (inputType === 'date' || inputType === 'datetime-local' || inputType === 'month') {
    return toISODate(value) || value || '';
  }
  return toDMYDate(value) || value || '';
};

/**
 * Handle radio button fill — works for both standard HTML radios
 * and Google Forms role="radio" elements.
 * DOM type determines behavior, not mapping type.
 * @param {HTMLElement} element - The radio element
 * @param {string} value - The value to match
 * @param {Object} [fieldConfig] - Config for the field (for aliases)
 * @returns {boolean} True if a radio was selected
 */
const handleRadioFill = (element, value, fieldConfig) => {
  const normalizedValue = normalizeOption(value);

  // Standard HTML radio (input[type="radio"])
  if (element.type === 'radio') {
    // Try alias match first (deterministic)
    const aliasMatch = tryAliasMatch(element, value, fieldConfig);
    if (aliasMatch) { selectOption(aliasMatch); return true; }

    // Try semantic match next (probabilistic)
    const semanticMatch = trySemanticOptionMatch(element, value);
    if (semanticMatch) { selectOption(semanticMatch); return true; }

    // Fallback: direct name-based group matching
    if (element.name) {
      const radios = document.querySelectorAll(`input[name="${element.name}"]`);
      for (const radio of radios) {
        const optionLabel = normalizeOption(getRadioOptionLabel(radio));
        const optionValue = normalizeOption(radio.value);
        if (optionLabel.includes(normalizedValue) || normalizedValue.includes(optionLabel) ||
            optionValue === normalizedValue) {
          radio.checked = true;
          radio.dispatchEvent(new Event("change", { bubbles: true }));
          return true;
        }
      }
    }
    return false;
  }

  // Google Forms radio (role="radio") — simulate click, never set .value
  if (element.getAttribute('role') === 'radio') {
    const optionText = normalizeOption(getGoogleRadioOptionText(element));
    if (optionText.includes(normalizedValue) || normalizedValue.includes(optionText)) {
      element.click();
      return true;
    }
    return false;
  }

  return false;
};

const fillField = (element, value, fieldConfig) => {
  if (!element || !value) {
    return false;
  }

  // ── Fill Engine: DOM determines HOW to fill ──────────────────
  // Mapping only provides WHAT to fill (value + options for alias matching).
  // All fill-strategy decisions are based on DOM element type.
  const isRadioEl = element.type === 'radio' || element.getAttribute('role') === 'radio';
  const isSelectEl = element.tagName === 'SELECT';
  const isGoogleListboxEl = element.getAttribute('role') === 'listbox';
  const domType = (element.type || element.tagName || '').toLowerCase();

  // RADIO HANDLING (DOM-driven)
  if (isRadioEl) {
    if (DEBUG) log(`Radio fill: "${value}"`, element.name || element.getAttribute('role'));
    return handleRadioFill(element, value, fieldConfig);
  }

  // GOOGLE LISTBOX (handled separately in Google Forms pass; skip here)
  if (isGoogleListboxEl) {
    return false;
  }

  // SELECT DROPDOWN
  if (isSelectEl) {
    // 1. Controlled Alias Match (Deterministic)
    const aliasMatch = tryAliasMatch(element, value, fieldConfig);
    if (aliasMatch) {
      selectOption(aliasMatch);
      return true;
    }

    // 2. Semantic Fallback (Probabilistic)
    const semanticResult = trySemanticOptionMatch(element, value);
    if (semanticResult) {
      selectOption(semanticResult);
      return true;
    }

    // 3. No match
    return false;
  }

  // --- DEFAULT: TEXT / TEXTAREA / NUMBER / URL / DATE / etc ---
  // DOM-driven date formatting: if element expects a date, format to YYYY-MM-DD
  let fillValue = String(value);
  if (domType === 'date' || domType === 'datetime-local' || domType === 'month') {
    fillValue = formatDateValue(value, domType);
    if (!fillValue) return false;
  }

  // Only count as filled if value actually changed
  const previousValue = element.value;
  element.value = fillValue;
  element.dispatchEvent(new Event("input", { bubbles: true }));
  element.dispatchEvent(new Event("change", { bubbles: true }));
  element.dispatchEvent(new Event("blur", { bubbles: true }));

  // Return true only if value actually changed
  return element.value !== previousValue && element.value.trim() !== '';
};

/**
 * Check if a field is safe to autofill
 * @param {HTMLElement} element - The form field element
 * @returns {boolean} True if safe to fill
 */
const isSafeToFill = (element) => {
  // Don't fill password fields
  if (element.type === "password") {
    return false;
  }

  // Don't fill hidden fields
  if (element.type === "hidden") {
    return false;
  }

  // Don't fill submit buttons
  if (element.type === "submit" || element.type === "button") {
    return false;
  }

  // For radio buttons, only skip if already checked
  // (value attribute is always non-empty, so checking element.value would block all radios)
  if (element.type === "radio") {
    return !element.checked;
  }

  // For select elements, always attempt to fill regardless of current selection
  // (the form's default first-option selection should not count as "user filled")
  if (element.tagName === "SELECT") {
    return true;
  }

  // Don't fill already-filled text fields
  if (element.value && element.value.trim() !== "") {
    return false;
  }

  return true;
};

/**
 * Check if a field already has a user-entered value.
 * Used to prevent re-filling already-filled fields and to filter
 * medium-confidence suggestions to unfilled fields only.
 * @param {HTMLElement} element - The form field element
 * @returns {boolean} True if the field already has a value
 */
const fieldHasUserValue = (element) => {
  if (!element) return false;

  // Radio: checked means already selected
  if (element.type === 'radio') {
    return element.checked;
  }

  // Google Forms radio container: check if any child radio is selected
  if (element.getAttribute && element.getAttribute('role') === 'radiogroup') {
    return !!element.querySelector('[role="radio"][aria-checked="true"]');
  }
  // For a role="radio" element directly
  if (element.getAttribute && element.getAttribute('role') === 'radio') {
    return element.getAttribute('aria-checked') === 'true';
  }

  // Google Forms listbox: check if a REAL (non-placeholder) option is selected.
  // Google Forms pre-selects the "Choose" placeholder with aria-selected="true"
  // on initial render, so we must ignore placeholder-like options.
  if (element.getAttribute && element.getAttribute('role') === 'listbox') {
    const selectedOptions = element.querySelectorAll('[aria-selected="true"]');
    for (const opt of selectedOptions) {
      const text = (opt.innerText || '').trim().toLowerCase();
      // Ignore common placeholder texts — these don't count as user selections
      if (text && text !== 'choose' && text !== 'select' && text !== '--' && text !== '') {
        return true;
      }
    }
    return false;
  }

  // Select: index > 0 means user picked something beyond the placeholder
  if (element.tagName === 'SELECT') {
    return element.selectedIndex > 0;
  }

  // Text/number/etc: non-empty trimmed value
  return !!(element.value && element.value.trim() !== '');
};

// ── Remote field mapping support ──────────────────────────────
// Single-endpoint design: GET /api/config/full
//
// Returns version + mappings in ONE HTTP round trip (down from two).
// The extension compares the returned version against its persisted value
// and skips re-processing when the version is unchanged.
//
// Network-call budget:
//   First load / version bump  → 1 request  (full payload)
//   Subsequent calls, same ver → 0 requests  (warm in-memory cache)
//   Cross-session, same ver    → 1 request   (cold map, full payload)
//
// Priority:
//   1. DB (via GET /api/config/full) — always preferred
//   2. FIELD_MAP_DEFAULTS — used only if DB is empty or unreachable
//
// For each DB entry:
//   • path, primary keywords  → taken from DB (admin-controlled)
//   • secondary, generic, negative, options, isDate, isNumeric,
//     requiredAnchors, numericAnchors, exclusionAnchors
//                             → filled from FIELD_MAP_DEFAULTS[key]
//                               (matching metadata not in admin UI)
//
// Security:
//  - Remote data validated: path = dot-notation, keywords = plain strings
//  - Prototype pollution blocked (__proto__, constructor, prototype keys)
//  - Data applied in-memory only — never stored to disk/storage
//  - No eval, no Function, no dynamic JS execution

// ── In-memory field-map cache ─────────────────────────────────
//
// Invariant (must always hold):
//   _fieldMapCache.map !== null  ⟺  _fieldMapCache.version !== null
//
//   Both fields are ALWAYS written together via _cacheStore() /
//   _cacheInvalidate() — never one without the other.
//
// Lifecycle:
//   Initial state      → { version: null, map: null }  (cold)
//   First load         → FETCH_FULL_CONFIG → _cacheStore() → warm
//   Same-session call  → version matches → re-apply map (0 network)
//   Version bump       → _cacheInvalidate() → FETCH_FULL_CONFIG → _cacheStore()
//   SW restart         → cold map, persisted version read from storage
//   DB empty / error   → defaults, cache UNTOUCHED (retry on next call)
//   Any exception      → defaults, _cacheInvalidate() (force retry)
//
// The cache is global and shared across all invocations of
// loadRemoteFieldMappings().  It is never keyed by user.
const _fieldMapCache = {
  /** @type {number|null} Server-reported version of the cached map */
  version: null,
  /** @type {Readonly<Object>|null} preprocessMappings() output for that version */
  map:     null,
};

/**
 * Atomically write version + processed map into the in-memory cache.
 * Both fields are always written together to preserve the invariant.
 *
 * @param {number}           version      - Server version number
 * @param {Readonly<Object>} processedMap - Output of preprocessMappings()
 */
const _cacheStore = (version, processedMap) => {
  _fieldMapCache.version = version;
  _fieldMapCache.map     = processedMap;
};

/**
 * Atomically null both cache fields.
 * The next loadRemoteFieldMappings() call will treat this as a cold cache
 * and perform a full FETCH_FULL_CONFIG request.
 *
 * Must be called on version bump and on any exception to prevent a stale
 * version value from silently suppressing future retries.
 */
const _cacheInvalidate = () => {
  _fieldMapCache.version = null;
  _fieldMapCache.map     = null;
};

// ── Persisted version (chrome.storage.local) ─────────────────
//
// Stores the last successfully-cached version number across service-worker
// restarts.  The service worker can be terminated at any time (MV3), wiping
// _fieldMapCache.  On restart, we read persistedVersion from storage and
// compare it against the version returned by FETCH_FULL_CONFIG:
//
//   persistedVersion == returned version → version unchanged; rebuild the
//     map from the payload (unavoidable — processed map can't be serialised)
//     but mark as "cache hit" so we know we can skip the bump path.
//
//   persistedVersion != returned version → genuine version bump; rebuild
//     and update persisted version.
//
// Key: 'fillr_config_version'  (namespaced to avoid collision)
// Value: integer | undefined

const STORAGE_VERSION_KEY = 'fillr_config_version';
const STORAGE_MAPPINGS_KEY = 'fillr_config_mappings';

/**
 * Read the persisted config version from chrome.storage.local.
 * Returns null if not yet set or on any storage error.
 *
 * @returns {Promise<number|null>}
 */
const _getPersistedVersion = () =>
  new Promise((resolve) => {
    chrome.storage.local.get([STORAGE_VERSION_KEY], (result) => {
      const v = result[STORAGE_VERSION_KEY];
      resolve(typeof v === 'number' ? v : null);
    });
  });

/**
 * Persist the successfully-cached version number to chrome.storage.local.
 * Fire-and-forget — errors are silently swallowed; a missing persisted
 * version just means a cold-cache rebuild on the next SW session.
 *
 * @param {number} version
 */
const _setPersistedVersion = (version) => {
  chrome.storage.local.set({ [STORAGE_VERSION_KEY]: version });
};

const _getPersistedMappings = () =>
  new Promise((resolve) => {
    chrome.storage.local.get([STORAGE_MAPPINGS_KEY], (result) => {
      const mappings = result[STORAGE_MAPPINGS_KEY];
      if (!mappings) {
        resolve(null);
        return;
      }
      resolve(mappings);
    });
  });

const _setPersistedMappings = (mappings) => {
  chrome.storage.local.set({ [STORAGE_MAPPINGS_KEY]: mappings });
};

// Transform backend array payload into V1 FIELD_MAP shape
const buildFieldMap = (mappingsArray = []) => {
  const map = {};
  mappingsArray.forEach((mapping) => {
    if (!mapping || !mapping.key) return;
    map[mapping.key] = {
      path: mapping.path,
      primary: mapping.primary || [],
      secondary: mapping.secondary || [],
      generic: mapping.generic || [],
      negative: mapping.negative || [],
      requiredAnchors: mapping.requiredAnchors || [],
      exclusionAnchors: mapping.exclusionAnchors || [],
      numericAnchors: mapping.numericAnchors || [],
      options: mapping.options || {},
      isNumeric: mapping.isNumeric || false,
      isDate: mapping.isDate || false,
    };
  });
  return map;
};

// Normalize server/storage payload shape to array
const normalizeMappingsArray = (mappings) => {
  if (Array.isArray(mappings)) return mappings;
  if (mappings && typeof mappings === 'object') {
    return Object.entries(mappings).map(([key, value]) => ({ key, ...(value || {}) }));
  }
  return [];
};

/**
 * Fetch field mappings from the server and rebuild FIELD_MAP.
 *
 * Uses GET /api/config/full — a single endpoint that returns both the
 * current version number and the full mapping payload.  This replaces the
 * old two-trip pattern (FETCH_CONFIG_VERSION → FETCH_FIELD_MAPPINGS).
 *
 * Call flow
 * ─────────
 *   ① Read persisted version from chrome.storage.local  (no network)
 *   ② In-memory fast path: if warm map AND persisted == cached version
 *        → re-apply cached map, return                  (0 network calls)
 *   ③ FETCH_FULL_CONFIG via background.js               (1 network call)
 *   ④ Version unchanged (server == in-memory cache)
 *        → re-apply warm map, update persisted version, return
 *   ⑤ Version changed / cold map
 *        → validate payload, pre-process, _cacheStore(),
 *          _setPersistedVersion(), FIELD_MAP = processedMap
 *   ⑥ DB empty / error → FIELD_MAP = defaults  (cache UNTOUCHED)
 *   ⑦ Any exception    → FIELD_MAP = defaults, _cacheInvalidate()
 */
const loadRemoteFieldMappings = async () => {
  try {
    // ── ① Persisted version (no network) ──────────────────────
    // Survives service-worker restarts; lets us detect genuinely-new versions
    // even after the module-level _fieldMapCache has been wiped.
    const persistedVersion = await _getPersistedVersion();

    // ── ② In-memory fast path (0 network) ─────────────────────
    // The warm map is current: persisted version matches the in-memory
    // cached version, so nothing has changed on the server since the last
    // successful fetch this session.  Re-apply and bail out immediately.
    if (
      _fieldMapCache.map !== null &&
      persistedVersion !== null &&
      persistedVersion === _fieldMapCache.version
    ) {
      FIELD_MAP = _fieldMapCache.map;
      if (DEBUG) log("FIELD_MAP keys:", Object.keys(FIELD_MAP));
      if (DEBUG) log(`Fast path: version=${persistedVersion} unchanged, map re-applied (0 network calls)`);
      return true;
    }

    // ── ③ Single-trip fetch  (version + mappings together) ────
    // One message → background.js → GET /api/config/full.
    // Replaces two separate messages (FETCH_CONFIG_VERSION + FETCH_FIELD_MAPPINGS).
    const resp = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "FETCH_FULL_CONFIG" }, resolve);
    });

    // ── ⑥ DB empty or server error ────────────────────────────
    // Fall back to hard-coded defaults.  Cache is intentionally NOT updated
    // so the next call retries rather than treating the error as "current."
    const respMappingsArray = normalizeMappingsArray(resp?.mappings);

    if (!resp?.success || respMappingsArray.length === 0) {
      const cachedMappings = await _getPersistedMappings();
      const cachedArray = normalizeMappingsArray(cachedMappings);
      if (cachedArray.length > 0) {
        const cachedProcessed = preprocessMappings(buildFieldMap(cachedArray));
        FIELD_MAP = cachedProcessed;
        if (persistedVersion !== null) {
          _cacheStore(persistedVersion, cachedProcessed);
        }
        if (DEBUG) log("FIELD_MAP keys:", Object.keys(FIELD_MAP));
        if (DEBUG) log('Config fetch failed — using persisted cached mappings');
        return true;
      }

      if (DEBUG) log('Config fetch failed and no cached mappings available');
      return false;
    }

    const returnedVersion = typeof resp.version === 'number' ? resp.version : null;

    // ── ④ Version unchanged, warm map available ────────────────
    // Server confirmed the version hasn't changed from what we have in memory.
    // Re-apply the existing processed map instead of re-tokenising everything.
    // This handles the common case where the SW restarted but the admin has
    // not made any mapping changes.
    if (
      returnedVersion !== null &&
      returnedVersion === _fieldMapCache.version &&
      _fieldMapCache.map !== null
    ) {
      FIELD_MAP = _fieldMapCache.map;
      _setPersistedVersion(returnedVersion); // refresh storage
      if (DEBUG) log(`Version match (v${returnedVersion}): map re-applied, no re-processing`);
      return true;
    }

    // ── ⑤ Version bump or cold cache: validate + build ────────
    const PATH_RE = /^[a-zA-Z0-9._-]+$/;
    const isValidPath = (p) =>
      typeof p === "string" && p.length > 0 && p.length <= 100 && PATH_RE.test(p);
    const isValidKeyword = (kw) =>
      typeof kw === "string" && kw.trim().length > 0 && kw.length <= 100;

    const newMap = {};

    const baseMap = buildFieldMap(respMappingsArray);

    // Build a lookup of RAW DB entries (before buildFieldMap normalisation)
    // so pick() can distinguish "field missing from DB" vs "field is empty []".
    const rawLookup = {};
    respMappingsArray.forEach(m => { if (m?.key) rawLookup[m.key] = m; });

    for (const [key, remote] of Object.entries(baseMap)) {
      // Block prototype pollution
      if (
        typeof key !== "string" ||
        key.length === 0 ||
        key.length > 60 ||
        key === "__proto__" ||
        key === "constructor" ||
        key === "prototype"
      ) {
        continue;
      }

      if (!isValidPath(remote?.path)) continue;

      const cleanPrimary = Array.isArray(remote?.primary)
        ? remote.primary.filter(isValidKeyword).map((kw) => kw.toLowerCase().trim()).slice(0, 30)
        : [];
      if (cleanPrimary.length === 0) continue;

      const cleanSecondary = Array.isArray(remote?.secondary)
        ? remote.secondary.filter(isValidKeyword).map((kw) => kw.toLowerCase().trim()).slice(0, 20)
        : [];
      const cleanGeneric = Array.isArray(remote?.generic)
        ? remote.generic.filter(isValidKeyword).map((kw) => kw.toLowerCase().trim()).slice(0, 10)
        : [];
      const cleanNegative = Array.isArray(remote?.negative)
        ? remote.negative.filter(isValidKeyword).map((kw) => kw.toLowerCase().trim()).slice(0, 20)
        : [];

      // Merge matching metadata: DB-first, with defaults as fallback.
      // buildFieldMap() normalises missing fields to []/{}/ false, which
      // masks "DB doesn't have this field" vs "DB explicitly set empty".
      // To distinguish, we check the RAW DB entry (before normalisation).
      const rawEntry = rawLookup[key] || {};
      const d = FIELD_MAP_DEFAULTS[key] || {};

      // Use raw DB value if it ACTUALLY exists in the DB document.
      // Fall back to hardcoded defaults otherwise.
      const pick = (rawField, defaultVal) => {
        if (rawField !== undefined) return rawField;
        return defaultVal;
      };

      newMap[key] = {
        path:      remote.path,
        primary:   cleanPrimary,
        secondary: cleanSecondary,
        generic:   cleanGeneric,
        negative:  cleanNegative,
        options:          pick(rawEntry.options,          d.options),
        isDate:           pick(rawEntry.isDate,           d.isDate),
        isNumeric:        pick(rawEntry.isNumeric,        d.isNumeric),
        requiredAnchors:  pick(rawEntry.requiredAnchors,  d.requiredAnchors),
        numericAnchors:   pick(rawEntry.numericAnchors,   d.numericAnchors),
        exclusionAnchors: pick(rawEntry.exclusionAnchors, d.exclusionAnchors),
      };
    }

    // Tokenise keyword arrays once; freeze the result.
    // _cacheStore() writes version + map atomically (invariant preserved).
    const processedMap = preprocessMappings(newMap);

    if (returnedVersion !== null) {
      _cacheStore(returnedVersion, processedMap);
      _setPersistedVersion(returnedVersion);
      _setPersistedMappings(respMappingsArray);
    }

    FIELD_MAP = processedMap;
    if (DEBUG) log("FIELD_MAP keys:", Object.keys(FIELD_MAP));

    if (DEBUG) {
      const action = persistedVersion === returnedVersion ? 'cold rebuild' : 'version bump';
      log(`FIELD_MAP rebuilt (${action}): ${Object.keys(newMap).length} entries, v${returnedVersion}`);
    }

    return true;

  } catch (_err) {
    console.error('[Content] Config fetch failed', _err);
    try {
      const persistedVersion = await _getPersistedVersion();
      const cachedMappings = await _getPersistedMappings();
      const cachedArray = normalizeMappingsArray(cachedMappings);

      if (cachedArray.length > 0) {
        const cachedProcessed = preprocessMappings(buildFieldMap(cachedArray));
        FIELD_MAP = cachedProcessed;
        if (persistedVersion !== null) {
          _cacheStore(persistedVersion, cachedProcessed);
        }
        if (DEBUG) log("FIELD_MAP keys:", Object.keys(FIELD_MAP));
        if (DEBUG) log('Exception during config fetch — using persisted cached mappings');
        return true;
      }
    } catch (_storageErr) {
      // swallow storage read errors and continue to graceful fail path
    }

    // ── ⑦ Any exception with no cached mappings ──────────────
    // Invalidate in-memory cache to allow a bounded fresh fetch on next call.
    _cacheInvalidate();
    if (DEBUG) log('Config unavailable: fetch failed and no cached mappings');
    return false;
  }
};

// (Remote field mapping fetch is triggered after FIELD_MAP declaration below)

/**
 * FIELD_MAP_DEFAULTS — Hard-coded fallback field mapping configuration.
 * Used ONLY when the server is unreachable or the DB has no entries.
 * The active FIELD_MAP (let, below) is always built from DB first.
 * These defaults also supply matching metadata (negative keywords, option
 * aliases, isDate/isNumeric flags, requiredAnchors) that the admin UI
 * does not manage — they are preserved regardless of DB state.
 */
const FIELD_MAP_DEFAULTS = {
  // --- IDENTITY ---
  uid: {
    path: "ids.uid",
    primary: [
      "uid",
      "university roll number",
      "roll number",
      "roll no",
      "registration number",
      "enrollment number",
    ],
    secondary: ["registration", "university id", "candidate id"],
    generic: ["id", "number"],
    negative: ["reference", "transaction", "payment", "receipt"],
  },
  university_roll_number: {
    path: "ids.uid", // Using same as uid for now
    primary: ["university roll number", "university roll no"],
    secondary: ["roll no", "roll number"],
    generic: ["roll"],
    negative: [],
  },
  
  gender: {
    path: "personal.gender",
    primary: ["gender", "student gender"],
    secondary: ["sex"],
    generic: ["male", "female"],
    negative: [],
    options: {
      Male: ["male", "m", "man"],
      Female: ["female", "f", "woman"],
      Other: ["other", "transgender"],
    },
  },
  dob: {
    path: "personal.dob",
    primary: ["date of birth", "dob", "birth date"],
    secondary: ["d.o.b", "birthdate"],
    generic: [],
    negative: [],
    isDate: true, // Special flag for date handling
  },
  age: {
    path: "personal.age",
    primary: ["age"],
    secondary: ["age in years"],
    generic: [],
    negative: ["months", "month"],
    isNumeric: true, // Only fill if field expects numeric
  },
  permanent_address: {
    path: "personal.permanent_address",
    primary: ["permanent address"],
    secondary: ["address", "residential address"],
    generic: [],
    negative: ["email", "contact", "correspondence"],
  },

  // --- CONTACT ---
  email: {
    path: "personal.email",
    primary: ["email", "email id", "personal email id", "email address"],
    secondary: ["personal email", "contact email", "primary email"],
    generic: ["mail"],
    negative: ["college email", "alternate", "parent", "guardian"],
  },
  phone: {
    path: "personal.phone",
    primary: [
      "mobile",
      "mobile number",
      "primary mobile number",
      "contact number",
    ],
    secondary: ["phone number", "contact no", "mob no", "phone"],
    generic: ["number"],
    negative: ["landline", "alternate", "parent", "guardian"],
  },

  // --- ACADEMICS ---
  //
  // Unit-test matrix (label → expected match)
  // ─────────────────────────────────────────────────────────────────────────
  // "10th percentage"                 → tenth_percentage      ✓
  // "12th percentage"                 → twelfth_percentage    ✓
  // "diploma percentage"              → diploma_percentage    ✓
  // "graduation percentage"           → graduation_percentage ✓
  // "ug percentage"                   → graduation_percentage ✓
  // "aggregate percentage"            → graduation_percentage ✓
  // "pg percentage"                   → pg_percentage         ✓
  // "post graduation percentage"      → pg_percentage         ✓
  // "masters percentage"              → pg_percentage         ✓
  // "mtech percentage"                → pg_percentage         ✓
  // "cgpa"                            → cgpa                  ✓
  // "cpi"                             → cgpa                  ✓
  // "gpa"                             → cgpa                  ✓
  // "cgpa / percentage"               → NONE (cgpa blocks %, % blocks cgpa)
  // "graduation cgpa"                 → cgpa (not graduation_percentage)
  // "pg cgpa"                         → cgpa (not pg_percentage)
  // "aggregate %"                     → graduation_percentage ✓
  // "overall percentage"              → graduation_percentage ✓
  // ─────────────────────────────────────────────────────────────────────────

  tenth_percentage: {
    path: "academics.tenth_percentage",
    primary: ["10th", "tenth", "class 10", "10th percentage", "class x"],
    secondary: ["ssc", "matriculation", "matric", "secondary"],
    generic: ["percentage", "percent", "marks", "score"],
    numericAnchors: ["10", "10th", "x"],
    negative: ["preferred", "expected"],
    // Block: "10th cgpa" or "class x cpi" — those are grade-point fields, not %
    exclusionAnchors: ["cgpa", "cpi", "gpa"],
  },
  twelfth_percentage: {
    path: "academics.twelfth_percentage",
    primary: ["12th", "twelfth", "class 12", "12th percentage", "class xii"],
    secondary: ["hsc", "senior secondary", "higher secondary"],
    generic: ["percentage", "percent", "marks", "score"],
    numericAnchors: ["12", "12th", "xii"],
    negative: ["preferred", "expected"],
    // Block: "12th cgpa" — grade-point field, not %
    exclusionAnchors: ["cgpa", "cpi", "gpa"],
  },
  diploma_percentage: {
    path: "academics.diploma_percentage",
    primary: ["diploma", "diploma percentage", "diploma %"],
    secondary: ["polytechnic", "diploma marks"],
    generic: ["percentage", "percent", "marks"],
    negative: ["preferred", "expected", "10th", "12th"],
    requiredAnchors: ["diploma", "polytechnic"],
    // Block: "diploma cgpa" — grade-point field, not %
    exclusionAnchors: ["cgpa", "cpi", "gpa"],
  },
  graduation_percentage: {
    path: "academics.graduation_percentage",
    primary: [
      "graduation percentage",
      "graduation %",
      "grad %",
      "grad.",
      "grad",
      "ug percentage",
      "undergraduate percentage",
      "aggregate percentage",
      "aggregate %",
      "agg percentage",
      "agg %",
      "overall percentage",
    ],
    secondary: [
      "degree percentage",
      "degree marks",
      "ug marks",
      "btech percentage",
      "be percentage",
    ],
    generic: ["percentage", "%", "marks"],
    negative: ["pg", "post graduation", "cgpa", "gpa", "masters", "mtech", "msc"],
    // At least ONE anchor must be present (OR logic).
    // Keeps generic labels like "percentage" from matching this slot entirely.
    requiredAnchors: ["grad", "graduation", "ug", "degree", "btech", "be", "aggregate", "agg", "overall"],
    // ANY of these present → hard block (score = 0).
    // Rule: "pg" / "post graduation" / "masters" / "mtech" / "msc" → pg_percentage
    // Rule: "cgpa" / "cpi" / "gpa" → cgpa field, not a percentage field
    exclusionAnchors: ["post graduation", "pg", "masters", "mtech", "msc", "cgpa", "cpi", "gpa"],
  },
  pg_percentage: {
    path: "academics.pg_percentage",
    primary: [
      "pg %",
      "pg percentage",
      "post graduation %",
      "post graduation percentage",
    ],
    secondary: ["masters percentage", "mtech percentage", "msc percentage"],
    generic: ["percentage", "%"],
    negative: ["grad", "graduation", "ug", "cgpa", "cpi", "gpa"],
    // At least ONE anchor must be present (OR logic).
    requiredAnchors: ["pg", "post graduation", "masters", "mtech", "msc"],
    // Block: "ug percentage", "graduation %" — those resolve to graduation_percentage
    // Block: "cgpa" / "cpi" / "gpa" — grade-point field, not %
    exclusionAnchors: ["ug", "graduation", "cgpa", "cpi", "gpa"],
  },
  cgpa: {
    path: "academics.cgpa",
    primary: ["cgpa", "cpi"],
    secondary: ["gpa", "cumulative grade point average"],
    generic: [],
    negative: ["percentage", "%", "marks"],
    // At least ONE of these must be present (OR logic).
    // Prevents generic "grade" / "score" labels from matching cgpa.
    requiredAnchors: ["cgpa", "cpi", "gpa"],
    // Block: pure percentage labels that happen to be inside a cgpa section heading
    // e.g. a form row that says "percentage (%)" should NOT match cgpa.
    // Note: "cgpa (%)" WOULD still match because "cgpa" satisfies requiredAnchors first,
    // and exclusionAnchors below only fire on labels that lack any cgpa/cpi/gpa token —
    // the requiredAnchors guard already catches that case.
    // Actual block: if the label is ONLY "%" with no cgpa token, requiredAnchors → 0.
    // No additional exclusionAnchors needed; requiredAnchors acts as the firewall.
    exclusionAnchors: [],
  },
  active_backlog: {
    path: "academics.active_backlog",
    primary: ["active backlog", "any active backlog", "current backlogs", "backlogs in current course"],
    secondary: ["backlogs", "backlog"],
    generic: [],
    negative: ["history", "count", "number", "no of"],
    options: {
      Yes: ["yes", "y", "true", "active", "have backlogs"],
      No: ["no", "n", "false", "clear", "all clear", "none", "0", "nil"],
    },
  },
  backlog_count: {
    path: "academics.backlog_count",
    primary: [
      "no of active backlog",
      "number of active backlogs",
      "count of backlogs",
      "number of backlog",
      "backlog count",
    ],
    secondary: ["how many backlogs"],
    generic: [],
    negative: [],
    isNumeric: true, // Only fill if field expects numeric
  },
  gap_months: {
    path: "academics.gap_months",
    primary: ["gap", "break in education", "gap in education"],
    secondary: ["education gap", "gap / break"],
    generic: ["months"],
    negative: ["year"],
    requiredAnchors: ["gap", "break"],
    isNumeric: true, // Only fill if field expects numeric
  },

  // --- EDUCATION METADATA ---
  batch: {
    path: "education.batch",
    primary: ["batch", "passing year", "year of passing", "passing out batch", "passout batch"],
    secondary: ["passout year", "pass out year", "passing out year"],
    generic: ["year"],
    negative: [],
    options: {
      "2023": ["2023"],
      "2024": ["2024"],
      "2025": ["2025"],
      "2026": ["2026"],
      "2027": ["2027"],
      "2028": ["2028"],
      "2029": ["2029"],
    },
  },
  program: {
    path: "education.program",
    primary: ["program", "degree", "course", "current course"],
    secondary: ["qualification", "pursuing"],
    generic: ["be", "btech", "mtech"],
    negative: [],
    options: {
      "B.E": ["b.e", "b.e.", "be", "bachelor of engineering"],
      "B.E+M.E (Integrated)": ["b.e+m.e", "integrated", "b.e + m.e", "dual degree"],
      "B.Tech": ["btech", "b.tech", "b.tech.", "bachelor of technology"],
      "M.Tech": ["mtech", "m.tech", "m.tech.", "master of technology"],
      MCA: ["mca", "master of computer applications"],
      BCA: ["bca", "bachelor of computer applications"],
      MBA: ["mba", "master of business administration"],
    },
  },
  stream: {
    path: "education.stream",
    primary: ["stream", "current stream", "branch", "specialization"],
    secondary: ["department"],
    generic: ["engg"],
    negative: [],
    options: {
      CSE: ["cse", "computer science", "cs", "computer science and engineering"],
      IT: ["information technology", "info tech", "it"],
      AIML: ["aiml", "ai ml", "artificial intelligence", "ai-ml", "ai", "ml"],
      BDA: ["bda", "big data analytics", "big data"],
      IoT: ["iot", "internet of things"],
      CC: ["cc", "cloud computing", "cloud"],
      GG: ["gg"],
      CSBS: ["csbs", "computer science business systems"],
      IS: ["is", "information security"],
      Blockchain: ["blockchain", "block chain"],
      Devops: ["devops", "dev ops"],
      ME: ["mechanical", "mech", "me"],
      CE: ["civil", "ce"],
      ECE: ["electronics", "electronics and communication", "ece"],
    },
  },
  college_name: {
    path: "education.college_name",
    primary: ["college name", "institute name", "name of college", "college"],
    secondary: ["institute", "university"],
    generic: ["campus"],
    negative: ["email", "id"],
  },

  // --- PLACEMENT ---
  position_applying: {
    path: "placement.position_applying",
    primary: ["position applying", "position applying for", "job role"],
    secondary: ["role", "applying for"],
    generic: ["position"],
    negative: [],
  },

  // --- LINKS ---
  github: {
    path: "links.github",
    primary: ["github", "github profile", "github url"],
    secondary: ["git repository"],
    generic: ["git"],
    negative: ["gitlab"],
  },
  linkedin: {
    path: "links.linkedin",
    primary: ["linkedin", "linkedin profile", "linkedin url"],
    secondary: ["linked in"],
    generic: ["proso file"],
    negative: [],
  },
  resume: {
    path: "links.resume",
    primary: ["resume", "resume link", "public resume link", "cv", "cv link"],
    secondary: ["curriculum vitae", "resume url", "resume drive link"],
    generic: ["link"],
    negative: ["upload", "attach", "file"],
  },
  job_location: {
    path: "placement.job_location",
    primary: ["job location", "job location preference", "preferred location", "location preference"],
    secondary: ["work location", "preferred work location"],
    generic: ["location"],
    negative: [],
  },
};

// ── Active FIELD_MAP — reassigned by loadRemoteFieldMappings() ──
// Starts as a pre-processed copy of FIELD_MAP_DEFAULTS (safe synchronous
// fallback). Replaced with a pre-processed DB-sourced map as soon as the
// async fetch completes. If DB is empty or unreachable, stays as defaults.
//
// Authoritative runtime map: always reflects the latest successfully-fetched
// and preprocessed config.  _fieldMapCache stores the same processed map so
// subsequent loadRemoteFieldMappings() calls can restore it without a
// network round-trip (cache hit) or discard it on a version bump (invalidate).
//
// All keyword arrays in FIELD_MAP are string[][] (pre-tokenised) so that
// calculateAdvancedScore and hasNumericAnchor never call tokenize() in the
// hot-path matching loop. preprocessMappings() is called exactly once per
// map build — never per field or per iteration.
const FIELD_MAP_DEFAULTS_PROCESSED = preprocessMappings(FIELD_MAP_DEFAULTS);
let FIELD_MAP = FIELD_MAP_DEFAULTS_PROCESSED;

// ── Fire remote mapping fetch (non-blocking) ──────────────────
// DB is checked immediately on load. FIELD_MAP is rebuilt from DB if
// the server responds with at least one mapping.
loadRemoteFieldMappings();

/**
 * Get value from nested object using dot-notation path
 * @param {Object} obj - The object to traverse
 * @param {string} path - Dot-notation path (e.g., "personal.name")
 * @returns {*} The value at the path, or undefined if not found
 */
const getValueByPath = (obj, path) => {
  const value = path.split(".").reduce((acc, key) => acc?.[key], obj);
  // Transform boolean values for active_backlog to Yes/No
  if (path === "academics.active_backlog" && typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  // Also handle string "true"/"false" for backwards compatibility
  if (path === "academics.active_backlog" && (value === "true" || value === "false")) {
    return value === "true" ? "Yes" : "No";
  }
  return value;
};

/**
 * Matching Engine Module (pure function)
 *
 * Find the best matching field using weighted keyword scoring.
 * No type-based blocking, no hard binary filters.
 * All anchors (required, numeric, exclusion) are handled as scoring
 * bonuses/penalties inside calculateAdvancedScore.
 *
 * Pipeline: normalizedLabel → tokenize → score all configs → best match + confidence
 *
 * @param {string} fieldText - Combined normalised text from label, placeholder, name, id
 * @returns {{bestMatch: string|null, score: number, confidence: number}}
 *   bestMatch  – FIELD_MAP key or null
 *   score      – raw integer score of best match
 *   confidence – normalised [0,1] confidence of best match
 */
const findBestMatchWithScore = (fieldText) => {
  const tokens = tokenize(fieldText);

  let bestMatch = null;
  let highestScore = 0;
  let bestConfidence = 0;

  for (const key in FIELD_MAP) {
    const config = FIELD_MAP[key];

    // Pure scoring — all anchors (numeric, required, exclusion) are
    // handled as bonuses/penalties inside calculateAdvancedScore.
    // No binary blocking here.
    const result = calculateAdvancedScore(tokens, config, key);

    if (DEBUG && result.score > 0) {
      log(
        `Score: "${fieldText.substring(0, 40)}" -> ${key} = ${result.score} (conf: ${result.confidence.toFixed(2)})`,
      );
    }

    if (result.score > highestScore) {
      highestScore = result.score;
      bestConfidence = result.confidence;
      bestMatch = key;
    }
  }

  if (DEBUG) {
    log(
      `Best Match: "${fieldText.substring(0, 40)}" -> ${bestMatch || "NONE"} (Score: ${highestScore}, Conf: ${bestConfidence.toFixed(2)})`,
    );
  }

  return { bestMatch, score: highestScore, confidence: bestConfidence };
};

/**
 * Orchestrator: Matching Engine + Value Resolver
 *
 * 1. Matching Engine: (normalizedLabel, FIELD_MAP) → bestMatch + confidence
 * 2. Value Resolver:  (profile, mapping.path) → value
 *
 * No type-based blocking. DOM type is irrelevant for matching.
 *
 * @param {Object} fieldData - Field metadata (label, placeholder, name, id)
 * @param {Object} profile   - User profile data
 * @returns {{value: *, matchKey: string|null, confidence: number}}
 */
const matchFieldToProfile = (fieldData, profile) => {
  const { label, placeholder, name, id } = fieldData;

  // Normalise once: lowercase, remove punctuation, collapse spaces.
  const combinedText = normalizeLabel(`${label} ${placeholder} ${name} ${id}`);

  // ── Matching Engine: pure scoring ──────────────────────────
  const { bestMatch, confidence } = findBestMatchWithScore(combinedText);

  if (!bestMatch || confidence < MEDIUM_CONFIDENCE) {
    if (DEBUG && confidence > 0)
      log(
        `Match Failed: "${combinedText.substring(0, 30)}..." -> Best: ${bestMatch} (conf: ${confidence.toFixed(2)})`,
      );
    return { value: null, matchKey: null, confidence };
  }

  if (DEBUG)
    log(
      `Matched: "${combinedText.substring(0, 30)}..." -> ${bestMatch} (conf: ${confidence.toFixed(2)})`,
    );

  // ── Value Resolver: pure path lookup ───────────────────────
  const config = FIELD_MAP[bestMatch];
  const value = getValueByPath(profile, config.path);

  return {
    value: value || null,
    matchKey: bestMatch,
    confidence,
  };
};

/**
 * Autofill all matching fields on the page using confidence scoring and learned mappings
 * Supports both standard HTML forms and Google Forms (click simulation)
 * @param {Object} profile - User profile data
 * @param {string} domain - Current domain name
 * @param {Object} siteMappings - Learned mappings for this domain
 * @param {Object} options - Autofill options
 * @param {boolean} [options.dryRun=false] - When true, detect/match only; do not write values
 * @returns {Promise<Object>} Results of autofill operation with pending confirmations
 */
const autofillPage = async (profile, domain = null, siteMappings = {}, options = {}) => {
  const dryRun = Boolean(options.dryRun);
  let autoFilledCount = 0;
  let candidateAutoFillCount = 0;
  const filledFields = [];
  const pendingConfirmations = [];
  const skippedFields = [];
  const learnedFills = [];

  // Reset registry for this run to avoid stale references across page changes.
  elementRegistry.clear();

  if (DEBUG || DIAG) {
    const mappingCount = FIELD_MAP ? Object.keys(FIELD_MAP).length : 0;
    diag('Autofill start', {
      host: window.location.host,
      isGoogleForm,
      dryRun,
      mappingCount,
    });
  }

  // Standard HTML form selectors
  const selectors = [
    'input[type="text"]',
    'input[type="email"]',
    'input[type="tel"]',
    'input[type="number"]',
    'input[type="url"]',
    "textarea",
    "select",
    'input[type="radio"]',
  ];

  let globalFieldIndex = 0;

  // --- Pass 1: Standard HTML form elements ---
  selectors.forEach((selector) => {
    const elements = document.querySelectorAll(selector);

    elements.forEach((element) => {
      // Check if safe to fill
      if (!isSafeToFill(element)) {
        skippedFields.push({
          reason: "unsafe or already filled",
          type: element.type,
          id: element.id || "no-id",
        });
        return;
      }

      // Generate unique field ID
      const fieldId = `field_${globalFieldIndex++}`;

      // Store element in registry
      elementRegistry.set(fieldId, element);

      // Get field metadata
      const fieldData = {
        label: getFieldLabel(element),
        placeholder: (element.placeholder || "").toLowerCase().trim(),
        name: (element.name || "").toLowerCase().trim(),
        id: (element.id || "").toLowerCase().trim(),
        type: element.type || element.tagName.toLowerCase(),
      };

      // Safety: skip unsafe labels
      const labelText =
        fieldData.label || fieldData.placeholder || fieldData.name || fieldId;
      if (isUnsafeLabel(labelText)) {
        skippedFields.push({
          reason: "unsafe label",
          label: labelText,
          type: fieldData.type,
        });
        return;
      }

      if (DEBUG && element.type === "radio") {
        log(
          `Processed Radio: ID=${element.id} Name=${element.name} Label="${fieldData.label}"`,
        );
      }

      const normalizedLabel = labelText.toLowerCase().trim();

      // Skip if field already has a user-entered value
      if (fieldHasUserValue(element)) {
        skippedFields.push({
          reason: 'already filled',
          label: labelText,
          type: fieldData.type,
        });
        return;
      }

      // CHECK LEARNED MAPPINGS FIRST (before confidence scoring)
      if (siteMappings[normalizedLabel]) {
        const learnedKey = siteMappings[normalizedLabel];
        const config = FIELD_MAP[learnedKey];

        if (config) {
          const value = getValueByPath(profile, config.path);

          if (value) {
            if (dryRun) {
              candidateAutoFillCount++;
              learnedFills.push({
                label: labelText,
                value: value,
                matchKey: learnedKey,
                learned: true,
                type: fieldData.type,
              });
              return;
            }

            // Route date fields through fillDateField
            const learnedFillSuccess = config.isDate
              ? fillDateField(element, value)
              : fillField(element, value, config);

            if (learnedFillSuccess) {
              autoFilledCount++;
              learnedFills.push({
                label: labelText,
                value: value,
                matchKey: learnedKey,
                learned: true,
                type: fieldData.type,
              });
              return; // Skip confidence scoring for learned fields
            }
          }
        }
      }

      // Try to match field to profile data with confidence score
      const matchResult = matchFieldToProfile(fieldData, profile);
      const { value, matchKey, confidence } = matchResult;

      if (value && matchKey) {
        // High confidence - auto-fill immediately
        if (confidence >= HIGH_CONFIDENCE) {
          const config = FIELD_MAP[matchKey];
          if (dryRun) {
            candidateAutoFillCount++;
            filledFields.push({
              label: labelText,
              value: value,
              matchKey: matchKey,
              confidence: confidence,
              type: fieldData.type,
            });
            return;
          }

          // Route date fields through fillDateField
          const success = config.isDate
            ? fillDateField(element, value)
            : fillField(element, value, config);

          if (success) {
            autoFilledCount++;
            filledFields.push({
              label: labelText,
              value: value,
              matchKey: matchKey,
              confidence: confidence,
              type: fieldData.type,
            });
          }

          // Debug: structured fill report (never log actual values in production)
          if (DEBUG) {
            log(`[FILL REPORT]`, {
              label: labelText,
              bestMatch: matchKey,
              score: confidence,
              confidence: confidence >= HIGH_CONFIDENCE ? 'HIGH' : 'MEDIUM',
              valueResolved: !!value,
              fillSuccess: success,
            });
          }
        }
        // Medium confidence - only suggest for unfilled fields
        else if (confidence >= MEDIUM_CONFIDENCE) {
          pendingConfirmations.push({
            fieldId: fieldId,
            labelText: labelText,
            suggestedKey: matchKey,
            suggestedValue: value,
            confidence: confidence,
            type: fieldData.type,
          });
          if (DEBUG) {
            log(`[FILL REPORT]`, {
              label: labelText,
              bestMatch: matchKey,
              score: confidence,
              confidence: 'MEDIUM (pending)',
              valueResolved: !!value,
              fillSuccess: false,
            });
          }
        }
      } else {
        skippedFields.push({
          reason:
            confidence < MEDIUM_CONFIDENCE ? "low confidence" : "no match",
          label: labelText,
          confidence: confidence || 0,
          type: fieldData.type,
        });
        if (DEBUG) {
          log(`[FILL REPORT]`, {
            label: labelText,
            bestMatch: matchKey || 'NONE',
            score: confidence || 0,
            confidence: 'SKIPPED',
            valueResolved: !!value,
            fillSuccess: false,
          });
        }
      }
    });
  });

  // ===== Pass 2: GOOGLE FORMS — Dropdown and Radio processing (click simulation) =====
  if (isGoogleForm) {
    // --- Process Google Form Dropdowns (role="listbox") ---
    const googleDropdowns = document.querySelectorAll('[role="listbox"]');
    for (const element of googleDropdowns) {
      const container = element.closest('[role="listitem"]');
      const heading = container?.querySelector('[role="heading"]');
      const labelText = (heading?.innerText || "").toLowerCase().trim();

      // Safety: skip empty/unsafe labels
      if (!labelText || isUnsafeLabel(labelText)) {
        skippedFields.push({
          reason: "unsafe or empty label",
          label: labelText,
          type: "google-dropdown",
        });
        continue;
      }

      const fieldId = `gd_${globalFieldIndex++}`;
      elementRegistry.set(fieldId, element);

      // Skip if dropdown already has a selected value
      if (fieldHasUserValue(element)) {
        skippedFields.push({
          reason: 'already filled',
          label: labelText,
          type: 'google-dropdown',
        });
        continue;
      }

      const fieldData = {
        label: labelText,
        placeholder: "",
        name: "",
        id: "",
        type: "google-dropdown",
      };
      const normalizedLabel = labelText;

      // Check learned mappings first
      if (siteMappings[normalizedLabel]) {
        const learnedKey = siteMappings[normalizedLabel];
        const config = FIELD_MAP[learnedKey];
        if (config) {
          const value = getValueByPath(profile, config.path);
          if (value) {
            if (dryRun) {
              candidateAutoFillCount++;
              learnedFills.push({
                label: labelText,
                value,
                matchKey: learnedKey,
                learned: true,
                type: "google-dropdown",
              });
              continue;
            }

            const filled = await fillGoogleDropdownHybrid(element, value, config);
            if (filled) {
              autoFilledCount++;
              learnedFills.push({
                label: labelText,
                value,
                matchKey: learnedKey,
                learned: true,
                type: "google-dropdown",
              });
              continue;
            }
          }
        }
      }

      // Confidence scoring
      const matchResult = matchFieldToProfile(fieldData, profile);
      const { value, matchKey, confidence } = matchResult;

      if (value && matchKey) {
        const config = FIELD_MAP[matchKey];
        if (confidence >= HIGH_CONFIDENCE) {
          if (dryRun) {
            candidateAutoFillCount++;
            filledFields.push({
              label: labelText,
              value,
              matchKey,
              confidence,
              type: "google-dropdown",
            });
            continue;
          }

          const filled = await fillGoogleDropdownHybrid(element, value, config);
          if (filled) {
            autoFilledCount++;
            filledFields.push({
              label: labelText,
              value,
              matchKey,
              confidence,
              type: "google-dropdown",
            });
          }
          if (DEBUG) {
            log(`[FILL REPORT]`, {
              label: labelText,
              bestMatch: matchKey,
              score: confidence,
              confidence: 'HIGH',
              valueResolved: !!value,
              fillSuccess: filled,
              fieldType: 'google-dropdown',
            });
          }
        } else if (confidence >= MEDIUM_CONFIDENCE) {
          pendingConfirmations.push({
            fieldId,
            labelText,
            suggestedKey: matchKey,
            suggestedValue: value,
            confidence,
            type: "google-dropdown",
          });
        }
      } else {
        skippedFields.push({
          reason: "no match",
          label: labelText,
          confidence: confidence || 0,
          type: "google-dropdown",
        });
      }
    }

    // --- Process Google Form Radios (role="radio"), grouped by question container ---
    const processedRadioContainers = new Set();
    const googleRadios = document.querySelectorAll('[role="radio"]');

    if (DEBUG) {
      log(`[RADIO DEBUG] Found ${googleRadios.length} total Google radio elements in document`);
    }

    for (const radio of googleRadios) {
      const container = radio.closest('[role="listitem"]');
      if (!container || processedRadioContainers.has(container)) continue;
      processedRadioContainers.add(container);

      const heading = container.querySelector('[role="heading"]');
      const labelText = (heading?.innerText || "").toLowerCase().trim();

      if (DEBUG) {
        log(`[RADIO DEBUG] Processing container:`, {
          headingText: heading?.innerText,
          labelText,
          containerRole: container.getAttribute('role'),
          radiosInContainer: container.querySelectorAll('[role="radio"]').length,
        });
      }

      // Safety: skip empty/unsafe labels
      if (!labelText || isUnsafeLabel(labelText)) {
        skippedFields.push({
          reason: "unsafe or empty label",
          label: labelText,
          type: "google-radio",
        });
        continue;
      }

      const fieldId = `gr_${globalFieldIndex++}`;
      elementRegistry.set(fieldId, container); // Store container for scoped confirmation

      const fieldData = {
        label: labelText,
        placeholder: "",
        name: "",
        id: "",
        type: "google-radio",
      };
      const normalizedLabel = labelText;

      // Check learned mappings first
      if (siteMappings[normalizedLabel]) {
        const learnedKey = siteMappings[normalizedLabel];
        const config = FIELD_MAP[learnedKey];
        if (config) {
          const value = getValueByPath(profile, config.path);
          if (value) {
            if (dryRun) {
              candidateAutoFillCount++;
              learnedFills.push({
                label: labelText,
                value,
                matchKey: learnedKey,
                learned: true,
                type: "google-radio",
              });
              continue;
            }

            const filled = fillGoogleRadioHybrid(value, config, container);
            if (filled) {
              autoFilledCount++;
              learnedFills.push({
                label: labelText,
                value,
                matchKey: learnedKey,
                learned: true,
                type: "google-radio",
              });
              continue;
            }
          }
        }
      }

      // Confidence scoring
      const matchResult = matchFieldToProfile(fieldData, profile);
      const { value, matchKey, confidence } = matchResult;

      if (DEBUG) {
        log(`[RADIO DEBUG] Match result for "${labelText}":`, {
          matchKey,
          value,
          confidence,
          meetsHighThreshold: confidence >= HIGH_CONFIDENCE,
        });
      }

      if (value && matchKey) {
        const config = FIELD_MAP[matchKey];
        if (confidence >= HIGH_CONFIDENCE) {
          if (dryRun) {
            candidateAutoFillCount++;
            filledFields.push({
              label: labelText,
              value,
              matchKey,
              confidence,
              type: "google-radio",
            });
            continue;
          }

          const filled = fillGoogleRadioHybrid(value, config, container);
          if (filled) {
            autoFilledCount++;
            filledFields.push({
              label: labelText,
              value,
              matchKey,
              confidence,
              type: "google-radio",
            });
          }
          if (DEBUG) {
            log(`[FILL REPORT]`, {
              label: labelText,
              bestMatch: matchKey,
              score: confidence,
              confidence: 'HIGH',
              valueResolved: !!value,
              fillSuccess: filled,
              fieldType: 'google-radio',
            });
          }
        } else if (confidence >= MEDIUM_CONFIDENCE) {
          pendingConfirmations.push({
            fieldId,
            labelText,
            suggestedKey: matchKey,
            suggestedValue: value,
            confidence,
            type: "google-radio",
          });
        }
      } else {
        skippedFields.push({
          reason: "no match",
          label: labelText,
          confidence: confidence || 0,
          type: "google-radio",
        });
      }
    }
  }

  return {
    status: dryRun ? "preview" : "completed",
    autoFilledCount: autoFilledCount,
    candidateAutoFillCount,
    filledFields: filledFields,
    learnedFills: learnedFills,
    pendingConfirmations: pendingConfirmations,
    skippedFields: skippedFields,
  };
};

// ── Page-level UI removed ─────────────────────────────────────
// All confirmation/result UI now lives exclusively in the extension popup.
// No floating divs, banners, or modals are injected into the page.

/**
 * Highlight an element on the page with a visual flash effect
 * @param {HTMLElement} element - Element to highlight
 * @param {boolean} scrollTo - Whether to scroll to the element (default: true)
 */
const highlightElement = (element, scrollTo = true) => {
  if (!element) return;
  
  // For Google Forms, find the question container
  let targetEl = element;
  if (isGoogleForm) {
    const questionContainer = element.closest('[role="listitem"]') || 
                              element.closest('.freebirdFormviewerComponentsQuestionBaseRoot') ||
                              element;
    targetEl = questionContainer;
  }
  
  // Scroll into view
  if (scrollTo) {
    targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  
  // Store original styles
  const originalOutline = targetEl.style.outline;
  const originalTransition = targetEl.style.transition;
  const originalBoxShadow = targetEl.style.boxShadow;
  
  // Apply highlight effect
  targetEl.style.transition = 'all 0.3s ease';
  targetEl.style.outline = '3px solid #f59e0b';
  targetEl.style.boxShadow = '0 0 20px rgba(245, 158, 11, 0.5)';
  
  // Flash animation
  setTimeout(() => {
    targetEl.style.outline = '3px solid #fbbf24';
    targetEl.style.boxShadow = '0 0 30px rgba(251, 191, 36, 0.7)';
  }, 300);
  
  setTimeout(() => {
    targetEl.style.outline = '3px solid #f59e0b';
    targetEl.style.boxShadow = '0 0 20px rgba(245, 158, 11, 0.5)';
  }, 600);
  
  // Remove highlight after 2 seconds
  setTimeout(() => {
    targetEl.style.outline = originalOutline;
    targetEl.style.boxShadow = originalBoxShadow;
    targetEl.style.transition = originalTransition;
  }, 2000);
};

/**
 * Message listener for communication with popup
 * Handles async autofill (Google Forms dropdowns require awaited click simulation)
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // PING used by popup to detect if content script is already injected
  if (request.action === "PING") {
    sendResponse({ pong: true });
    return;
  }

  // Highlight a single field (scroll to it and flash highlight)
  if (request.action === "HIGHLIGHT_FIELD") {
    const element = elementRegistry.get(request.fieldId);
    if (element && document.contains(element)) {
      highlightElement(element);
      sendResponse({ success: true });
    } else {
      sendResponse({ success: false, error: "Field not found" });
    }
    return;
  }

  // Highlight all pending fields
  if (request.action === "HIGHLIGHT_ALL_FIELDS") {
    let highlighted = 0;
    const firstElement = elementRegistry.get(request.fieldIds[0]);
    
    request.fieldIds.forEach((fieldId, index) => {
      const element = elementRegistry.get(fieldId);
      if (element && document.contains(element)) {
        // Stagger the highlights slightly
        setTimeout(() => highlightElement(element, index === 0), index * 100);
        highlighted++;
      }
    });
    
    sendResponse({ success: true, highlighted });
    return;
  }

  if (request.action === "SCAN_PAGE") {
    const detectedFields = detectFormFields();
    sendResponse({
      success: true,
      fields: detectedFields,
      url: window.location.href,
      title: document.title,
    });
  }

  if (request.action === "AUTOFILL_PAGE") {
    // Delay for Google Forms to ensure all elements are rendered
    const delay = isGoogleForm ? 800 : 0;

    setTimeout(async () => {
      try {
        const configReady = await loadRemoteFieldMappings();
        if (!configReady) {
          sendResponse({
            status: 'config_unavailable',
            message: 'Configuration unavailable.',
          });
          return;
        }

        // Run autofill directly — high confidence fills silently,
        // medium confidence is routed to popup only. No page-level UI.
        const result = await autofillPage(
          request.profile,
          request.domain,
          request.siteMappings,
        );

        // Proactively notify popup of medium-confidence fields
        if (result.pendingConfirmations && result.pendingConfirmations.length > 0) {
          chrome.runtime.sendMessage({
            action: 'MEDIUM_CONFIDENCE_RESULTS',
            fields: result.pendingConfirmations
          });
        }

        log(`Autofill complete: ${result.autoFilledCount} filled, ${result.pendingConfirmations?.length || 0} pending review`);

        sendResponse(result);
      } catch (err) {
        console.error("[Content] Autofill error:", err);
        sendResponse({ status: "error", error: err.message });
      }
    }, delay);
  }

  // Apply a single medium-confidence field from popup
  if (request.action === "APPLY_MEDIUM_FILL") {
    (async () => {
      const element = elementRegistry.get(request.fieldId);
      if (!element || !document.contains(element)) {
        sendResponse({ success: false, error: 'Field not found or detached' });
        return;
      }

      const config = FIELD_MAP[request.matchKey];
      if (!config) {
        sendResponse({ success: false, error: 'No config for key: ' + request.matchKey });
        return;
      }

      let success = false;
      const value = request.value;

      // Route through Google Forms handlers based on fieldId prefix
      if (request.fieldId.startsWith('gd_')) {
        success = await fillGoogleDropdownHybrid(element, value, config);
      } else if (request.fieldId.startsWith('gr_')) {
        success = fillGoogleRadioHybrid(value, config, element);
      } else if (config.isDate) {
        success = fillDateField(element, value);
      } else {
        success = fillField(element, value, config);
      }

      sendResponse({ success });
    })();
  }

  return true; // Keep message channel open for async responses
});
