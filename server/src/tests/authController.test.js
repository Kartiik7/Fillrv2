/**
 * authController.test.js — Unit tests for register/login Joi validation
 *
 * Tests the schema-level validation logic without a real DB connection.
 * DB calls (User.create, User.findOne) are mocked.
 */

jest.mock('../models/User', () => ({
  findOne: jest.fn(),
  create:  jest.fn(),
}));
jest.mock('../services/metricsService', () => ({
  incrementMetric: jest.fn(),
  trackActiveUser: jest.fn(),
}));
jest.mock('../services/logger', () => ({
  error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn(),
}));
jest.mock('../services/auditService', () => ({
  createAuditLog: jest.fn(),
  logAdminAction: jest.fn(),
}));
jest.mock('../controllers/verificationController', () => ({
  sendVerificationEmail: jest.fn(),
}));

const { register, login } = require('../controllers/authController');
const User = require('../models/User');
const { createAuditLog } = require('../services/auditService');

// ── Helpers ───────────────────────────────────────────────────
const makeReq = (body) => ({ body, ip: '127.0.0.1' });
const makeRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json   = jest.fn().mockReturnValue(res);
  return res;
};

describe('authController.register — Joi validation', () => {
  it('rejects missing email', async () => {
    const res = makeRes();
    const next = jest.fn();
    await register(makeReq({ password: 'ValidPass1' }), res, next);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: false }));
  });

  it('rejects invalid email format', async () => {
    const res = makeRes();
    const next = jest.fn();
    await register(makeReq({ email: 'not-an-email', password: 'ValidPass1' }), res, next);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects weak password (too short)', async () => {
    const res = makeRes();
    const next = jest.fn();
    await register(makeReq({ email: 'user@test.com', password: 'abc' }), res, next);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects password missing uppercase/number', async () => {
    const res = makeRes();
    const next = jest.fn();
    await register(makeReq({ email: 'user@test.com', password: 'alllowercase' }), res, next);
    expect(res.status).toHaveBeenCalledWith(400);
  });
});

describe('authController.login — Joi validation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('rejects missing password', async () => {
    const res = makeRes();
    const next = jest.fn();
    await login(makeReq({ email: 'user@test.com' }), res, next);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('rejects missing email', async () => {
    const res = makeRes();
    const next = jest.fn();
    await login(makeReq({ password: 'ValidPass1' }), res, next);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  it('blocks suspended account with ACCOUNT_SUSPENDED and writes audit log', async () => {
    const res = makeRes();
    const next = jest.fn();

    User.findOne.mockResolvedValue({
      _id: '507f1f77bcf86cd799439011',
      authProvider: 'local',
      isSuspended: true,
      matchPassword: jest.fn().mockResolvedValue(true),
    });

    await login(makeReq({ email: 'user@test.com', password: 'ValidPass1' }), res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      code: 'ACCOUNT_SUSPENDED',
      message: 'Access denied.',
    });
    expect(createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      action: 'ACCOUNT_SUSPENDED_LOGIN_ATTEMPT',
      metadata: { channel: 'AUTH' },
    }));
  });
});
