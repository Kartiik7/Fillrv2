describe('resetController.forgotPassword', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    process.env = {
      ...originalEnv,
      RESEND_API_KEY: 'test-resend-key',
      RESEND_FROM: 'Fillr <noreply@fillr.app>',
      FRONTEND_URL: 'https://fillr.app/',
    };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('sends a clean reset-password link without the legacy .html path', async () => {
    const sendMock = jest.fn().mockResolvedValue({ data: { id: 'email_123' }, error: null });
    const user = {
      resetPasswordHash: null,
      resetPasswordExpiry: null,
      save: jest.fn().mockResolvedValue(undefined),
    };
    const selectMock = jest.fn().mockResolvedValue(user);
    const findOneMock = jest.fn(() => ({ select: selectMock }));

    jest.doMock('../models/User', () => ({
      findOne: findOneMock,
    }));
    jest.doMock('../services/logger', () => ({
      error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn(),
    }));
    jest.doMock('../services/metricsService', () => ({
      incrementMetric: jest.fn(),
    }));
    jest.doMock('resend', () => ({
      Resend: jest.fn(() => ({
        emails: {
          send: sendMock,
        },
      })),
    }));

    const { forgotPassword } = require('../controllers/resetController');

    const req = { body: { email: 'user@test.com' } };
    const res = {
      json: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
    };
    const next = jest.fn();

    await forgotPassword(req, res, next);
    await new Promise((resolve) => setImmediate(resolve));

    expect(res.json).toHaveBeenCalledWith({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.',
    });
    expect(next).not.toHaveBeenCalled();
    expect(user.save).toHaveBeenCalledWith({ validateBeforeSave: false });
    expect(sendMock).toHaveBeenCalledTimes(1);

    const emailPayload = sendMock.mock.calls[0][0];
    expect(emailPayload.html).toContain('https://fillr.app/reset-password?token=');
    expect(emailPayload.html).not.toContain('/reset-password.html?token=');
  });
});