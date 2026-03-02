/**
 * LifetimeMetric.js — Singleton lifetime aggregated metrics
 *
 * Stores running totals that are updated incrementally alongside daily metrics.
 * This avoids expensive aggregation over all SystemMetric documents.
 */

const mongoose = require('mongoose');

const lifetimeMetricSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      default: 'global',
      immutable: true,
    },
    registrations: {
      type: Number,
      default: 0,
    },
    logins: {
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
  },
  { versionKey: false }
);

lifetimeMetricSchema.index({ key: 1 }, { unique: true });

module.exports = mongoose.model('LifetimeMetric', lifetimeMetricSchema);