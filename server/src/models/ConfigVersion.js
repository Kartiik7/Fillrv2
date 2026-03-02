/**
 * ConfigVersion.js — Tracks field mapping configuration version
 *
 * The extension checks this version number to decide whether to
 * refetch the full field mappings — reduces unnecessary API calls.
 *
 * Only one document exists in this collection (singleton pattern).
 */

const mongoose = require('mongoose');

const configVersionSchema = new mongoose.Schema(
  {
    version: {
      type: Number,
      required: true,
      default: 1,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { versionKey: false }
);

/**
 * Atomically increment the version and return the new document.
 * Creates the singleton document if it doesn't exist (upsert).
 */
configVersionSchema.statics.bump = async function () {
  return this.findOneAndUpdate(
    {},
    { $inc: { version: 1 }, $set: { updatedAt: new Date() } },
    { upsert: true, new: true }
  );
};

/**
 * Get the current version (creates with version=1 if missing).
 */
configVersionSchema.statics.current = async function () {
  let doc = await this.findOne().lean();
  if (!doc) {
    doc = await this.create({ version: 1 });
  }
  return doc;
};

module.exports = mongoose.model('ConfigVersion', configVersionSchema);
