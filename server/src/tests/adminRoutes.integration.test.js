/**
 * adminRoutes.integration.test.js
 *
 * Integration-style tests for new admin endpoints by mounting the real router
 * and mocking middleware/models (no DB connection needed).
 */

jest.mock('../middleware/authMiddleware', () => (
  (req, _res, next) => {
    req.user = { _id: '507f1f77bcf86cd799439011' };
    next();
  }
));

jest.mock('../middleware/adminMiddleware', () => (
  (_req, _res, next) => next()
));

jest.mock('../models/SystemMetric', () => ({
  findOne: jest.fn(),
  aggregate: jest.fn(),
}));

jest.mock('../models/LifetimeMetric', () => ({
  findOne: jest.fn(),
}));

jest.mock('../models/ConfigVersion', () => ({
  current: jest.fn(),
  bump: jest.fn(),
}));

jest.mock('../models/AuditLog', () => ({
  find: jest.fn(),
}));

jest.mock('../models/ExtensionKey', () => ({
  countDocuments: jest.fn(),
}));

jest.mock('../models/User', () => ({
  countDocuments: jest.fn(),
  findById: jest.fn(),
  updateOne: jest.fn(),
  deleteOne: jest.fn(),
  ROLES: { USER: 'user', ADMIN: 'admin' },
}));

jest.mock('../models/FieldMapping', () => ({
  find: jest.fn(),
  findOne: jest.fn(),
  countDocuments: jest.fn(),
  updateMany: jest.fn(),
  updateOne: jest.fn(),
  findOneAndUpdate: jest.fn(),
  findOneAndDelete: jest.fn(),
  bulkWrite: jest.fn(),
}));

jest.mock('../services/auditService', () => ({
  logAdminAction: jest.fn(),
}));

jest.mock('../services/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

const express = require('express');
const http = require('http');
const adminRoutes = require('../routes/adminRoutes');
const SystemMetric = require('../models/SystemMetric');
const LifetimeMetric = require('../models/LifetimeMetric');
const ConfigVersion = require('../models/ConfigVersion');
const AuditLog = require('../models/AuditLog');
const ExtensionKey = require('../models/ExtensionKey');
const User = require('../models/User');
const FieldMapping = require('../models/FieldMapping');
const { logAdminAction } = require('../services/auditService');

const createChain = (terminalValue) => ({
  sort: jest.fn().mockReturnThis(),
  skip: jest.fn().mockReturnThis(),
  limit: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  lean: jest.fn().mockResolvedValue(terminalValue),
});

const createSelectLeanChain = (terminalValue) => ({
  select: jest.fn().mockReturnValue({
    lean: jest.fn().mockResolvedValue(terminalValue),
  }),
});

describe('adminRoutes new endpoints', () => {
  let server;
  let baseUrl;

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/admin', adminRoutes);

    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  const requestJson = async (path) => {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: { Authorization: 'Bearer test-token' },
    });
    const body = await res.json();
    return { status: res.status, body };
  };

  const requestWithMethodJson = async (path, method, payload) => {
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        Authorization: 'Bearer test-token',
        'Content-Type': 'application/json',
      },
      body: payload ? JSON.stringify(payload) : undefined,
    });

    const body = await res.json();
    return { status: res.status, body };
  };

  it('GET /api/admin/system-health returns computed health with totalRequests denominator', async () => {
    SystemMetric.findOne.mockReturnValue({
      select: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue({
          apiErrors: 4,
          totalRequests: 100,
          extensionAuthRequests: 20,
          loginRequests: 10,
          lastApiErrorAt: '2026-03-02T10:00:00.000Z',
        }),
      }),
    });

    const { status, body } = await requestJson('/api/admin/system-health');

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.errorRateToday).toBe(4.0);
    expect(body.data.lastApiErrorTimestamp).toBe('2026-03-02T10:00:00.000Z');
  });

  it('GET /api/admin/system-health falls back to extensionAuth+login denominator', async () => {
    SystemMetric.findOne.mockReturnValue({
      select: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue({
          apiErrors: 3,
          totalRequests: 0,
          extensionAuthRequests: 40,
          loginRequests: 20,
          lastApiErrorAt: null,
        }),
      }),
    });

    const { status, body } = await requestJson('/api/admin/system-health');

    expect(status).toBe(200);
    expect(body.data.errorRateToday).toBe(5.0);
    expect(body.data.lastApiErrorTimestamp).toBeNull();
  });

  it('GET /api/admin/security-summary returns numeric summaries', async () => {
    User.countDocuments.mockResolvedValue(2);
    ExtensionKey.countDocuments
      .mockResolvedValueOnce(15)
      .mockResolvedValueOnce(4);

    const { status, body } = await requestJson('/api/admin/security-summary');

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data).toEqual({
      activeAdminCount: 2,
      totalSecretKeysIssued: 15,
      revokedSecretKeysCount: 4,
      suspiciousAuthAttemptsTracked: false,
      suspiciousAuthAttempts: null,
    });
  });

  it('GET /api/admin/audit?limit=5 returns action + createdAt only', async () => {
    AuditLog.find.mockReturnValue(createChain([
      { action: 'USER_DELETE', createdAt: '2026-03-01T11:00:00.000Z', adminId: 'x', ip: '1.1.1.1' },
      { action: 'USER_ROLE_CHANGE', createdAt: '2026-03-01T12:00:00.000Z', metadata: { a: 1 } },
    ]));

    const { status, body } = await requestJson('/api/admin/audit?limit=5');

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.count).toBe(2);
    expect(body.data.items).toEqual([
      { action: 'USER_DELETE', createdAt: '2026-03-01T11:00:00.000Z' },
      { action: 'USER_ROLE_CHANGE', createdAt: '2026-03-01T12:00:00.000Z' },
    ]);
  });

  it('GET /api/admin/config/version returns formatted version payload', async () => {
    ConfigVersion.current.mockResolvedValue({
      version: 7,
      updatedAt: '2026-03-02T09:00:00.000Z',
    });

    const { status, body } = await requestJson('/api/admin/config/version');

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data).toEqual({
      version: 'v7.0.0',
      numericVersion: 7,
      updatedAt: '2026-03-02T09:00:00.000Z',
    });
  });

  it('GET /api/admin/metrics/summary reads lifetime totals from LifetimeMetric doc', async () => {
    SystemMetric.findOne.mockReturnValue({
      lean: jest.fn().mockResolvedValue({
        userRegistrations: 2,
        loginRequests: 3,
        extensionAuthRequests: 4,
        passwordResetRequests: 1,
        apiErrors: 1,
        activeUsers: ['u1', 'u2'],
      }),
    });

    SystemMetric.aggregate.mockResolvedValue([
      {
        registrations: 10,
        logins: 12,
        extensionAuth: 8,
        passwordResets: 3,
        errors: 2,
        activeUsersNested: [['u1', 'u2'], ['u2', 'u3']],
      },
    ]);

    LifetimeMetric.findOne.mockReturnValue({
      lean: jest.fn().mockResolvedValue({
        registrations: 50,
        logins: 80,
        extensionAuthRequests: 30,
        passwordResetRequests: 12,
        apiErrors: 6,
      }),
    });

    User.countDocuments.mockResolvedValue(200);

    const { status, body } = await requestJson('/api/admin/metrics/summary');

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.total).toEqual({
      registrations: 50,
      logins: 80,
      extensionAuth: 30,
      passwordResets: 12,
      errors: 6,
    });
    expect(SystemMetric.aggregate).toHaveBeenCalledTimes(1);
    expect(LifetimeMetric.findOne).toHaveBeenCalledWith({ key: 'global' });
  });

  it('GET /api/admin/mappings/debug-match returns top match with score and confidence', async () => {
    FieldMapping.find.mockReturnValue({
      select: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue([
          {
            key: 'first_name',
            primary: ['first name', 'given name'],
            secondary: ['name'],
            generic: [],
            negative: [],
          },
          {
            key: 'last_name',
            primary: ['last name', 'surname'],
            secondary: ['name'],
            generic: [],
            negative: [],
          },
        ]),
      }),
    });

    const { status, body } = await requestJson('/api/admin/mappings/debug-match?label=First%20Name');

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.topMatch).toBe('first_name');
    expect(body.score).toBeGreaterThan(0);
    expect(body.confidence).toBeGreaterThan(0);
  });

  it('PATCH /api/admin/users/:id/role blocks self demotion with structured code and audit log', async () => {
    const selfId = '507f1f77bcf86cd799439011';

    const { status, body } = await requestWithMethodJson(
      `/api/admin/users/${selfId}/role`,
      'PATCH',
      { role: 'user' }
    );

    expect(status).toBe(403);
    expect(body).toEqual({
      success: false,
      code: 'ADMIN_SELF_MODIFICATION_BLOCKED',
      message: 'Action blocked.',
    });
    expect(logAdminAction).toHaveBeenCalledWith(expect.objectContaining({
      action: 'ADMIN_SELF_MODIFICATION_BLOCKED',
      metadata: expect.objectContaining({
        operation: 'ROLE_CHANGE',
        reason: 'SELF_MODIFICATION',
      }),
    }));
  });

  it('DELETE /api/admin/users/:id blocks self deletion with structured code and audit log', async () => {
    const selfId = '507f1f77bcf86cd799439011';

    const { status, body } = await requestWithMethodJson(
      `/api/admin/users/${selfId}`,
      'DELETE'
    );

    expect(status).toBe(403);
    expect(body).toEqual({
      success: false,
      code: 'ADMIN_SELF_MODIFICATION_BLOCKED',
      message: 'Action blocked.',
    });
    expect(logAdminAction).toHaveBeenCalledWith(expect.objectContaining({
      action: 'ADMIN_SELF_MODIFICATION_BLOCKED',
      metadata: expect.objectContaining({
        operation: 'USER_DELETE',
        reason: 'SELF_MODIFICATION',
      }),
    }));
  });

  it('DELETE /api/admin/users/:id blocks deleting the last remaining admin', async () => {
    User.findById.mockReturnValue({
      select: jest.fn().mockReturnValue({
        lean: jest.fn().mockResolvedValue({
          _id: '507f1f77bcf86cd799439022',
          role: 'admin',
          email: 'admin@example.com',
        }),
      }),
    });
    User.countDocuments.mockResolvedValue(1);

    const { status, body } = await requestWithMethodJson(
      '/api/admin/users/507f1f77bcf86cd799439022',
      'DELETE'
    );

    expect(status).toBe(403);
    expect(body).toEqual({
      success: false,
      code: 'ADMIN_SELF_MODIFICATION_BLOCKED',
      message: 'Action blocked.',
    });
    expect(logAdminAction).toHaveBeenCalledWith(expect.objectContaining({
      action: 'ADMIN_SELF_MODIFICATION_BLOCKED',
      metadata: expect.objectContaining({
        operation: 'USER_DELETE',
        reason: 'LAST_ADMIN_DELETE_BLOCKED',
      }),
    }));
    expect(User.deleteOne).not.toHaveBeenCalled();
  });

  it('PATCH /api/admin/field-mappings/:key/reorder moves rank up within the same group', async () => {
    const key = 'university_roll_number';

    FieldMapping.findOne
      .mockReturnValueOnce(createSelectLeanChain({
        _id: '507f1f77bcf86cd799439099',
        key,
        path: 'ids.uid',
        order: 3,
        orderGroup: 'ids',
      }))
      .mockReturnValueOnce(createSelectLeanChain({ order: 3 }))
      .mockReturnValueOnce(createSelectLeanChain({
        key,
        path: 'ids.uid',
        order: 2,
        orderGroup: 'ids',
        fieldType: 'text',
        primary: ['university roll number'],
        secondary: [],
        generic: [],
        negative: [],
        options: undefined,
        updatedAt: '2026-03-16T10:00:00.000Z',
      }));

    FieldMapping.find.mockImplementation(() => ({
      select: jest.fn().mockReturnValue({
        // ensureOrderMetadata path: .select(...).lean()
        lean: jest.fn().mockResolvedValue([
          { _id: 'a1', key: 'uid', path: 'ids.uid', order: 1, orderGroup: 'ids' },
          { _id: 'a2', key: 'reg_no', path: 'ids.reg_no', order: 2, orderGroup: 'ids' },
          { _id: 'a3', key: 'university_roll_number', path: 'ids.uid', order: 3, orderGroup: 'ids' },
        ]),
        // normalizeGroupOrders path: .select(...).sort(...).lean()
        sort: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue([
            { _id: 'a1', key: 'uid', order: 1, createdAt: '2026-03-16T09:00:00.000Z' },
            { _id: 'a2', key: 'reg_no', order: 2, createdAt: '2026-03-16T09:01:00.000Z' },
            { _id: 'a3', key: 'university_roll_number', order: 3, createdAt: '2026-03-16T09:02:00.000Z' },
          ]),
        }),
      }),
    }));

    FieldMapping.updateOne.mockResolvedValue({ acknowledged: true, modifiedCount: 1 });
    FieldMapping.updateMany.mockResolvedValue({ acknowledged: true, modifiedCount: 1 });
    FieldMapping.bulkWrite.mockResolvedValue({ acknowledged: true, modifiedCount: 0 });
    FieldMapping.countDocuments.mockResolvedValue(3);
    ConfigVersion.bump.mockResolvedValue({ version: 12 });

    const { status, body } = await requestWithMethodJson(
      `/api/admin/field-mappings/${key}/reorder`,
      'PATCH',
      { direction: 'up' }
    );

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(FieldMapping.updateMany).toHaveBeenCalledWith(
      {
        orderGroup: 'ids',
        key: { $ne: key },
        order: { $gte: 2, $lt: 3 },
      },
      { $inc: { order: 1 } },
      undefined
    );
    expect(FieldMapping.updateOne).toHaveBeenNthCalledWith(
      2,
      { key },
      { $set: { order: 2, updatedAt: expect.any(Date) } },
      undefined
    );
    expect(ConfigVersion.bump).toHaveBeenCalledTimes(1);
    expect(logAdminAction).toHaveBeenCalledWith(expect.objectContaining({
      action: 'FIELD_MAPPING_REORDER',
      metadata: expect.objectContaining({ fieldId: key, from: 3, to: 2, orderGroup: 'ids' }),
    }));
  });

  it('PATCH /api/admin/field-mappings/:key/reorder rejects payload containing both direction and order', async () => {
    const { status, body } = await requestWithMethodJson(
      '/api/admin/field-mappings/uid/reorder',
      'PATCH',
      { direction: 'down', order: 2 }
    );

    expect(status).toBe(400);
    expect(body.success).toBe(false);
    expect(body.message).toBe('Provide exactly one of direction or order.');
  });

  it('GET /api/admin/field-mappings returns order metadata sorted for admin display', async () => {
    const finalRaw = [
      {
        key: 'uid',
        path: 'ids.uid',
        orderGroup: 'ids',
        order: 1,
        fieldType: 'text',
        primary: ['uid'],
        secondary: [],
        generic: [],
        negative: [],
        options: undefined,
        updatedAt: '2026-03-16T10:00:00.000Z',
      },
    ];

    const ensureSelect = jest.fn().mockReturnValue({
      lean: jest.fn().mockResolvedValue(finalRaw.map((m) => ({
        _id: 'doc1',
        key: m.key,
        path: m.path,
        orderGroup: m.orderGroup,
        order: m.order,
      }))),
    });

    const normalizeSort = jest.fn().mockReturnValue({
      lean: jest.fn().mockResolvedValue([
        { _id: 'doc1', key: 'uid', order: 1, createdAt: '2026-03-16T10:00:00.000Z' },
      ]),
    });
    const normalizeSelect = jest.fn().mockReturnValue({ sort: normalizeSort });

    const finalSort = jest.fn().mockReturnValue({
      lean: jest.fn().mockResolvedValue(finalRaw),
    });
    const finalSelect = jest.fn().mockReturnValue({ sort: finalSort });

    FieldMapping.find
      .mockReturnValueOnce({ select: ensureSelect })
      .mockReturnValueOnce({ select: normalizeSelect })
      .mockReturnValueOnce({ select: finalSelect });

    const { status, body } = await requestJson('/api/admin/field-mappings');

    expect(status).toBe(200);
    expect(body.success).toBe(true);
    expect(finalSort).toHaveBeenCalledWith({ orderGroup: 1, order: 1, key: 1 });
    expect(body.mappings[0]).toEqual(expect.objectContaining({
      key: 'uid',
      orderGroup: 'ids',
      order: 1,
    }));
  });
});

