/**
 * logger.js — Centralized logger service
 *
 * Uses a lightweight, leveled logging approach.
 * In production: only warn/error are shown, timestamps included.
 * In development: full debug output with colors.
 *
 * Levels: error > warn > info > debug
 */

const isProd = process.env.NODE_ENV === 'production';

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const CURRENT_LEVEL = isProd ? LEVELS.warn : LEVELS.debug;

function timestamp() {
  return new Date().toISOString();
}

function shouldLog(level) {
  return LEVELS[level] <= CURRENT_LEVEL;
}

const logger = {
  error(message, ...args) {
    if (shouldLog('error')) {
      console.error(`[${timestamp()}] [ERROR] ${message}`, ...args);
    }
  },
  warn(message, ...args) {
    if (shouldLog('warn')) {
      console.warn(`[${timestamp()}] [WARN] ${message}`, ...args);
    }
  },
  info(message, ...args) {
    if (shouldLog('info')) {
      console.info(`[${timestamp()}] [INFO] ${message}`, ...args);
    }
  },
  debug(message, ...args) {
    if (shouldLog('debug')) {
      console.debug(`[${timestamp()}] [DEBUG] ${message}`, ...args);
    }
  },
};

module.exports = logger;
