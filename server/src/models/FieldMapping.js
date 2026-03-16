/**
 * FieldMapping.js — Stores field mapping configuration
 *
 * Used by the extension to map form labels → user profile paths.
 * Managed exclusively by admin users via /api/admin/field-mappings.
 * Read publicly (no auth) via GET /api/config/field-mappings.
 *
 * Keyword categories:
 *  primary   — high-confidence labels that strongly identify the field (≥1 required)
 *  secondary — moderate-confidence patterns
 *  generic   — low-specificity / shared terms used as a fallback
 *  negative  — terms that DISQUALIFY this field (must not match)
 *
 * Security:
 *  - No eval, no regex injection, no dynamic JS execution
 *  - All keyword arrays must contain plain strings (validated by Joi at route level)
 *  - Strict schema: only whitelisted fields are stored
 */

const mongoose = require('mongoose');

const strArray = (required, maxLen) => ({
  type: [String],
  required: !!required,
  default: required ? undefined : [],
  validate: required
    ? { validator: (arr) => arr.length >= 1 && arr.length <= maxLen, message: `primary must have 1-${maxLen} entries.` }
    : { validator: (arr) => arr.length <= maxLen, message: `Array must have at most ${maxLen} entries.` },
});

const fieldMappingSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      maxlength: 100,
    },
    path: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },
    // Field input type for the user-facing dashboard form
    fieldType: {
      type: String,
      enum: ['text', 'number', 'date', 'email', 'tel', 'url', 'textarea', 'select'],
      default: 'text',
    },
    // High-confidence labels — required, at least 1
    primary:   strArray(true,  30),
    // Moderate-confidence patterns — optional
    secondary: strArray(false, 20),
    // Low-specificity fallback terms — optional
    generic:   strArray(false, 10),
    // Terms that disqualify this field — optional
    negative:  strArray(false, 20),
    // Dropdown options for select-type fields.
    // Stored as key → aliases: e.g. { "B.Tech": ["btech", "bachelor of technology"] }
    // Profile data is stored in plaintext intentionally: the autofill engine
    // must read the canonical value to fill forms. Hashing profile data would
    // break autofill — only passwords and tokens are hashed (bcrypt, server-side).
    options: {
      type: Map,
      of: [String],
      default: undefined,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

// Index on key for fast lookups
fieldMappingSchema.index({ key: 1 }, { unique: true });

module.exports = mongoose.model('FieldMapping', fieldMappingSchema);
