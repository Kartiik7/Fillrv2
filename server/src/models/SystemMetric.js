/**
 * SystemMetric.js — Daily aggregated system metrics
 *
 * One document per calendar day (YYYY-MM-DD).
 * Updated incrementally via $inc and $addToSet — no full-document rewrites.
 *
 * Security:
 *  - No PII stored (activeUsers stores only ObjectId references)
 *  - Read only by admin via /api/admin/metrics/summary
 *  - Never exposed to regular users
 */

const mongoose = require('mongoose');

const systemMetricSchema = new mongoose.Schema(
  {
    date: {
      type: String,
      required: true,
      match: /^\d{4}-\d{2}-\d{2}$/,
    },
    userRegistrations: {
      type: Number,
      default: 0,
    },
    loginRequests: {
      type: Number,
      default: 0,
    },
    extensionAuthRequests: {
      type: Number,
      default: 0,
    },
    passwordResetRequests: {
      type: Number,
      default: 0,
    },
    apiErrors: {
      type: Number,
      default: 0,
    },
    lastApiErrorAt: {
      type: Date,
      default: null,
    },
    totalRequests: {
      type: Number,
      default: 0,
    },
    activeUsers: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
  },
  { versionKey: false }
);

// Unique index on date — one document per day
systemMetricSchema.index({ date: 1 }, { unique: true });

module.exports = mongoose.model('SystemMetric', systemMetricSchema);
