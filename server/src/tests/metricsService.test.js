/**
 * metricsService.test.js — Unit tests for the metrics service
 *
 * Tests:
 *  - incrementMetric rejects unknown fields (no DB call)
 *  - incrementMetric accepts known fields
 *  - trackActiveUser skips falsy userId
 */

// Mock mongoose model to avoid real DB connection
jest.mock('../models/SystemMetric', () => ({
  updateOne: jest.fn().mockReturnValue(Promise.resolve()),
}));

jest.mock('../models/LifetimeMetric', () => ({
  updateOne: jest.fn().mockReturnValue(Promise.resolve()),
}));

// Mock config
jest.mock('../config/config', () => ({
  metrics: {
    allowedFields: [
      'userRegistrations',
      'loginRequests',
      'extensionAuthRequests',
      'passwordResetRequests',
      'apiErrors',
      'totalRequests',
    ],
  },
}));

// Mock logger to suppress output in tests
jest.mock('../services/logger', () => ({
  error: jest.fn(),
  warn:  jest.fn(),
  info:  jest.fn(),
  debug: jest.fn(),
}));

const SystemMetric = require('../models/SystemMetric');
const LifetimeMetric = require('../models/LifetimeMetric');
const { incrementMetric, trackActiveUser } = require('../services/metricsService');

describe('metricsService.incrementMetric', () => {
  beforeEach(() => {
    SystemMetric.updateOne.mockClear();
    LifetimeMetric.updateOne.mockClear();
  });

  it('does NOT call updateOne for an unknown field', () => {
    incrementMetric('hackerField');
    expect(SystemMetric.updateOne).not.toHaveBeenCalled();
    expect(LifetimeMetric.updateOne).not.toHaveBeenCalled();
  });

  it('calls updateOne for daily and lifetime counters for mapped fields', () => {
    incrementMetric('userRegistrations');
    expect(SystemMetric.updateOne).toHaveBeenCalledWith(
      expect.objectContaining({ date: expect.any(String) }),
      { $inc: { userRegistrations: 1 } },
      { upsert: true }
    );
    expect(LifetimeMetric.updateOne).toHaveBeenCalledWith(
      { key: 'global' },
      { $inc: { registrations: 1 }, $setOnInsert: { key: 'global' } },
      { upsert: true }
    );
  });

  it('increments lifetime for all mapped fields, excluding totalRequests', () => {
    const fields = [
      'userRegistrations', 'loginRequests', 'extensionAuthRequests',
      'passwordResetRequests', 'apiErrors', 'totalRequests',
    ];
    fields.forEach(f => incrementMetric(f));
    expect(SystemMetric.updateOne).toHaveBeenCalledTimes(fields.length);
    expect(LifetimeMetric.updateOne).toHaveBeenCalledTimes(5);
  });
});

describe('metricsService.trackActiveUser', () => {
  beforeEach(() => {
    SystemMetric.updateOne.mockClear();
    LifetimeMetric.updateOne.mockClear();
  });

  it('does NOT call updateOne for falsy userId', () => {
    trackActiveUser(null);
    trackActiveUser(undefined);
    trackActiveUser('');
    expect(SystemMetric.updateOne).not.toHaveBeenCalled();
    expect(LifetimeMetric.updateOne).not.toHaveBeenCalled();
  });

  it('calls updateOne for a valid userId', () => {
    trackActiveUser('user123');
    expect(SystemMetric.updateOne).toHaveBeenCalledWith(
      expect.objectContaining({ date: expect.any(String) }),
      { $addToSet: { activeUsers: 'user123' } },
      { upsert: true }
    );
  });
});
