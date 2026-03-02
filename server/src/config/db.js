/**
 * db.js — MongoDB connection
 *
 * Protects against:
 *  - Hardcoded connection strings: MONGO_URI from environment only
 *  - Connection-string leakage in logs: host logged only in dev mode
 *  - Raw Mongo errors sent to client: errors caught here, generic message only
 *  - Mongo connection leak: serverSelectionTimeoutMS fails fast on bad config
 */

const mongoose = require('mongoose');
const logger   = require('../services/logger');

const isProd = process.env.NODE_ENV === 'production';

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000, // Fail fast — prevents hanging on bad URI
    });
    // In production, do NOT log the host (connection string may be in env logs)
    if (!isProd) {
      logger.info(`[DB] Connected: ${conn.connection.host}`);
    } else {
      logger.info('[DB] MongoDB connected.');
    }
  } catch (error) {
    // Log without exposing the full connection string or stack
    logger.error('[DB] Connection failed. Verify MONGO_URI environment variable.');
    process.exit(1);
  }
};

module.exports = connectDB;
