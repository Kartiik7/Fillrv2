/**
 * matcher.js — Pure Matching & Scoring Engine
 *
 * This module contains all pure (no-DOM, no-API) functions that power
 * Fillr's field matching logic. Keeping these separate from content.js
 * means they can be tested in isolation and reused across scripts.
 *
 * Loaded via manifest.json as a content script BEFORE content.js,
 * making all exports available as globals to the main content script.
 *
 * Separation of concerns:
 *  - matcher.js   → Pure logic: scoring, tokenizing, normalizing
 *  - content.js   → DOM: detecting fields, autofilling, message handling
 */

'use strict';

// ── Confidence Thresholds ─────────────────────────────────────
/**
 * Minimum score for a semantic (fuzzy) dropdown/radio match to be accepted.
 * Raise to reduce false-positive fills; lower to be more permissive.
 * Range: 0.0 (accept all) – 1.0 (exact match only).
 * Recommended: 0.6
 */
const MATCH_CONFIDENCE_THRESHOLD = 0.6;

/** Score treat as high confidence — used in some fill-decision logic */
const HIGH_CONFIDENCE = 0.75;
/** Score treated as medium confidence */
const MEDIUM_CONFIDENCE = 0.5;

// ── String Normalization ──────────────────────────────────────
/**
 * Normalize option text for fuzzy matching.
 * Lowercases, strips punctuation, collapses whitespace.
 *
 * @param {string} text
 * @returns {string} Normalized string
 */
const normalizeOption = (text) => {
  if (!text) return '';
  return String(text)
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
};

/**
 * Normalize a field label (or any text) into a clean, matchable string.
 * Performs all transformations in a single pass:
 *   • Lowercases once
 *   • Expands Roman-numeral class / grade shorthands
 *   • Converts % to the word "percentage"
 *   • Replaces / and - with spaces
 *   • Strips remaining punctuation
 *   • Collapses and trims whitespace
 *
 * Idempotent — safe to call on already-normalised strings.
 * Used internally by tokenize(); call it directly when you need a
 * normalised string without splitting into tokens.
 *
 * @param {string} text
 * @returns {string} Normalised string (not yet split into tokens)
 */
const normalizeLabel = (text) => {
  if (!text) return '';
  return String(text)
    .toLowerCase()
    // Class-level shorthands — xii before x to avoid partial replacement
    .replace(/\bclass\s+xii\b/g,        'class 12')
    .replace(/\bclass\s+x\b/g,          'class 10')
    // Ordinal forms
    .replace(/\bxiith\b/g,              '12th')
    .replace(/\bxth\b/g,               '10th')
    // Standalone Roman numerals
    .replace(/\bxii\b/g,               '12')
    .replace(/\bx\b/g,                 '10')
    // "grad" / "grad." → "graduation"
    .replace(/\bgrad\.?(?=[^a-z]|$)/g, 'graduation')
    // Symbols → words / spaces
    .replace(/%/g,                      ' percentage ')
    .replace(/[\/\-]/g,                 ' ')
    // Strip all remaining non-alphanumeric characters
    .replace(/[^a-z0-9 ]/g,            ' ')
    // Collapse whitespace
    .replace(/\s+/g,                   ' ')
    .trim();
};

// ── Tokenization ──────────────────────────────────────────────
/**
 * Tokenize text into individual words.
 * Delegates all normalisation to normalizeLabel() so the two are
 * always in sync — normalizeLabel once, then split.
 *
 * @param {string} text
 * @returns {string[]} Array of lowercase tokens
 */
const tokenize = (text) => {
  if (!text) return [];
  return normalizeLabel(text).split(' ').filter(t => t.length > 0);
};

// ── Scoring Functions ─────────────────────────────────────────
/**
 * Calculate similarity score between two normalized strings.
 * Uses exact > contains > token overlap tiering.
 *
 * @param {string} target - Candidate string (e.g. option text)
 * @param {string} query  - Query string (e.g. profile value)
 * @returns {number} Score in [0, 1]
 */
const calculateOptionScore = (target, query) => {
  if (!target || !query) return 0;
  if (target === query)           return 1.0;
  if (target.includes(query))     return 0.8;
  if (query.includes(target))     return 0.7;

  const queryTokens  = query.split(' ');
  const targetTokens = target.split(' ');
  const commonTokens = queryTokens.filter(t => targetTokens.includes(t));

  if (commonTokens.length > 0) {
    return Math.min(0.6, commonTokens.length * 0.2);
  }
  return 0;
};

/**
 * Calculate weighted keyword score for a form field.
 *
 * Point values:
 *   primary match      → +5
 *   secondary match    → +3
 *   generic match      → +1
 *   negative match     → −5
 *
 * Scoring bonuses (NOT hard blocks):
 *   requiredAnchors    → +3 bonus if ANY present
 *   numericAnchors     → +4 bonus if ANY present
 *   exclusionAnchors   → −8 penalty if ANY present
 *
 * @param {string[]} tokens - Tokenized field text (from tokenize())
 * @param {Object}   config - Pre-processed field config (use preprocessConfig/preprocessMappings)
 * @param {string[][]} [config.primary]          - Pre-tokenised strong signal keywords          (+5 each)
 * @param {string[][}} [config.secondary]        - Pre-tokenised moderate signal keywords         (+3 each)
 * @param {string[][]} [config.generic]          - Pre-tokenised weak signal keywords             (+1 each)
 * @param {string[][]} [config.negative]         - Pre-tokenised penalizing keywords              (−5 each)
 * @param {string[][]} [config.requiredAnchors]  - Bonus when present (+3)
 * @param {string[][]} [config.numericAnchors]   - Bonus when present (+4)
 * @param {string[][]} [config.exclusionAnchors] - Penalty when present (−8)
 * @param {string}   [key='']                  - Identifier for the matched field
 * @returns {{ key: string, score: number, confidence: number }}
 *   score      – raw integer point total (floored at 0)
 *   confidence – score normalised to [0, 1] via fixed baseline
 */
const calculateAdvancedScore = (tokens, config, key = '') => {
  const {
    primary          = [],
    secondary        = [],
    generic          = [],
    negative         = [],
    requiredAnchors  = [],
    exclusionAnchors = [],
    numericAnchors   = [],
  } = config;

  // Fixed baseline for confidence normalisation.
  // A single primary match (5) → 5/6 = 0.83 → HIGH_CONFIDENCE.
  // A single secondary (3) → 3/6 = 0.50 → MEDIUM_CONFIDENCE.
  // A single generic  (1) → 1/6 = 0.17 → below threshold (skip).
  // This prevents configs with many keywords from deflating confidence.
  const SCORE_BASELINE = 6;

  // requiredAnchors: BONUS, not a hard block.
  // If any required anchor is present → bonus points.
  // If none present → no bonus, but score is NOT zeroed out.
  let anchorBonus = 0;
  if (requiredAnchors.length > 0) {
    const anyPresent = requiredAnchors.some(kwTokens =>
      kwTokens.every(t => tokens.includes(t))
    );
    if (anyPresent) {
      anchorBonus = 3;
    }
  }

  // numericAnchors: BONUS, not a hard block.
  // Distinguishes e.g. "10th marks" from "12th marks" via comparative scoring.
  let numericBonus = 0;
  if (numericAnchors.length > 0) {
    const anyPresent = numericAnchors.some(kwTokens =>
      kwTokens.every(t => tokens.includes(t))
    );
    if (anyPresent) {
      numericBonus = 4;
    }
  }

  // exclusionAnchors: PENALTY, not a hard block.
  // Heavy penalty makes it near-impossible for excluded configs to win,
  // but doesn't zero out the score unconditionally.
  let exclusionPenalty = 0;
  if (exclusionAnchors.length > 0) {
    const anyPresent = exclusionAnchors.some(kwTokens =>
      kwTokens.every(t => tokens.includes(t))
    );
    if (anyPresent) {
      exclusionPenalty = -8;
    }
  }

  let score = anchorBonus + numericBonus + exclusionPenalty;

  // Keyword arrays are pre-tokenised (string[][]) — iterate token arrays directly.
  primary.forEach(kwTokens => {
    if (kwTokens.every(t => tokens.includes(t))) score += 5;
  });
  secondary.forEach(kwTokens => {
    if (kwTokens.every(t => tokens.includes(t))) score += 3;
  });
  generic.forEach(kwTokens => {
    if (kwTokens.every(t => tokens.includes(t))) score += 1;
  });
  negative.forEach(kwTokens => {
    if (kwTokens.every(t => tokens.includes(t))) score -= 5;
  });

  score = Math.max(0, score);

  // Confidence normalised against a fixed baseline for consistent thresholds
  // across configs with varying keyword counts.
  const confidence = score > 0 ? Math.min(1.0, score / SCORE_BASELINE) : 0;

  return { key, score, confidence };
};

/**
 * Check whether at least one numeric anchor token is present in the
 * tokenized field text. Used to distinguish e.g. "10th marks" from "12th marks".
 *
 * @param {string[]}   tokens         - Tokenized field text
 * @param {string[][]} numericAnchors - Pre-tokenised required anchors (e.g. [["10th"]])
 * @returns {boolean} True if any anchor matches (or no anchors required)
 */
const hasNumericAnchor = (tokens, numericAnchors) => {
  if (!numericAnchors || numericAnchors.length === 0) return true;
  // numericAnchors is pre-tokenised (string[][]) — no re-tokenisation needed.
  return numericAnchors.some(kwTokens =>
    kwTokens.every(t => tokens.includes(t))
  );
};

// ── Mapping Preprocessors ─────────────────────────────────────
/**
 * Pre-tokenise all keyword arrays in a single raw field config.
 * Each keyword string is converted to its token array once, so the
 * hot-path scoring loop never calls tokenize() per iteration.
 *
 * Returns a frozen object — keyword arrays must not be mutated after
 * preprocessing.
 *
 * @param {Object} config - Raw field config with string[] keyword arrays
 * @returns {Readonly<Object>} Config where keyword arrays are string[][]
 */
const preprocessConfig = (config) => {
  const tok = (arr) => (Array.isArray(arr) ? arr : []).map(kw => tokenize(String(kw)));
  return Object.freeze({
    primary:          tok(config.primary),
    secondary:        tok(config.secondary),
    generic:          tok(config.generic),
    negative:         tok(config.negative),
    requiredAnchors:  tok(config.requiredAnchors),
    numericAnchors:   tok(config.numericAnchors),
    exclusionAnchors: tok(config.exclusionAnchors),
  });
};

/**
 * Pre-process every entry in a raw field-mappings object.
 * All keyword arrays are tokenised once; the resulting map is frozen.
 *
 * Call this exactly once — after fetching or building the map — never
 * inside a per-field or per-iteration loop.
 *
 * Non-keyword fields (path, options, isDate, isNumeric, …) are
 * preserved unchanged via object spread; preprocessConfig() overwrites
 * keyword arrays with pre-tokenised form.
 *
 * @param {Object} rawMappings - Map of fieldKey → raw config
 * @returns {Readonly<Object>} Frozen map of fieldKey → processed config
 */
const preprocessMappings = (rawMappings) => {
  const processed = {};
  for (const key of Object.keys(rawMappings)) {
    const raw = rawMappings[key];
    processed[key] = Object.freeze({
      ...raw,                    // preserve path, options, isDate, isNumeric, …
      ...preprocessConfig(raw), // overwrite keyword arrays with pre-tokenised form
    });
  }
  return Object.freeze(processed);
};
