/**
 * logger.test.js — Unit tests for the logger service
 *
 * Tests:
 *  - Logger methods exist and are callable
 *  - In 'production' mode, debug/info should NOT call console.* 
 *  - In 'development' mode, all levels should call console.*
 */

describe('Logger service', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
    jest.resetModules();
  });

  it('exports error, warn, info, debug methods', () => {
    const logger = require('../services/logger');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.debug).toBe('function');
  });

  it('does not call console.info or console.debug in production mode', () => {
    process.env.NODE_ENV = 'production';
    const logger = require('../services/logger');

    const infoSpy  = jest.spyOn(console, 'info').mockImplementation(() => {});
    const debugSpy = jest.spyOn(console, 'debug').mockImplementation(() => {});

    logger.info('should be silent in prod');
    logger.debug('should be silent in prod');

    expect(infoSpy).not.toHaveBeenCalled();
    expect(debugSpy).not.toHaveBeenCalled();

    infoSpy.mockRestore();
    debugSpy.mockRestore();
  });

  it('calls console.error in production mode', () => {
    process.env.NODE_ENV = 'production';
    const logger = require('../services/logger');
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

    logger.error('test error');
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it('calls console.info in development mode', () => {
    process.env.NODE_ENV = 'development';
    jest.resetModules();
    const logger = require('../services/logger');
    const spy = jest.spyOn(console, 'info').mockImplementation(() => {});

    logger.info('test info');
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});
