/**
 * keyController.test.js — Unit tests for extension auth suspension handling
 */

jest.mock('bcryptjs', () => ({
  compare: jest.fn(),
  hash: jest.fn(),
}));

jest.mock('uuid', () => ({
  v4: jest.fn(() => '00000000-0000-4000-8000-000000000000'),
}));

jest.mock('../models/User', () => ({
  findById: jest.fn(),
}));

jest.mock('../models/ExtensionKey', () => ({
  findOne: jest.fn(),
  find: jest.fn(),
  updateOne: jest.fn(),
}));

jest.mock('../controllers/authController', () => ({
  generateToken: jest.fn(() => 'test-token'),
}));

jest.mock('../services/metricsService', () => ({
  incrementMetric: jest.fn(),
  trackActiveUser: jest.fn(),
}));

jest.mock('../services/auditService', () => ({
  createAuditLog: jest.fn(),
  logAdminAction: jest.fn(),
}));

const bcrypt = require('bcryptjs');
const User = require('../models/User');
const ExtensionKey = require('../models/ExtensionKey');
const { createAuditLog } = require('../services/auditService');
const { incrementMetric, trackActiveUser } = require('../services/metricsService');
const { extensionAuth } = require('../controllers/keyController');

const makeReq = (body) => ({ body, ip: '127.0.0.1' });
const makeRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

describe('keyController.extensionAuth', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('blocks suspended user with ACCOUNT_SUSPENDED and logs audit attempt', async () => {
    const req = makeReq({ apiKey: 'fillr_TEST-KEY-123' });
    const res = makeRes();
    const next = jest.fn();

    ExtensionKey.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue({
        _id: 'ext_key_1',
        userId: '507f1f77bcf86cd799439011',
        hashedKey: 'hash-value',
      }),
    });

    bcrypt.compare.mockResolvedValue(true);

    User.findById.mockReturnValue({
      select: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue({
          _id: '507f1f77bcf86cd799439011',
          isSuspended: true,
        }),
      }),
    });

    await extensionAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      success: false,
      code: 'ACCOUNT_SUSPENDED',
      message: 'Access denied.',
    });

    expect(createAuditLog).toHaveBeenCalledWith(expect.objectContaining({
      action: 'ACCOUNT_SUSPENDED_EXTENSION_AUTH_ATTEMPT',
      metadata: { channel: 'EXTENSION_AUTH' },
    }));

    expect(incrementMetric).not.toHaveBeenCalled();
    expect(trackActiveUser).not.toHaveBeenCalled();
  });
});
