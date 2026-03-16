/**
 * app.cors.test.js — CORS preflight coverage for admin reorder endpoint
 */

const http = require('http');
jest.mock('../routes/authRoutes', () => {
  const express = require('express');
  return express.Router();
});
jest.mock('../routes/profileRoutes', () => {
  const express = require('express');
  return express.Router();
});
jest.mock('../routes/userRoutes', () => {
  const express = require('express');
  return express.Router();
});
jest.mock('../routes/keyRoutes', () => {
  const express = require('express');
  return express.Router();
});
jest.mock('../routes/configRoutes', () => {
  const express = require('express');
  return express.Router();
});
jest.mock('../routes/adminRoutes', () => {
  const express = require('express');
  return express.Router();
});

process.env.RESEND_API_KEY = process.env.RESEND_API_KEY || 're_test_key';
const app = require('../app');

describe('app CORS preflight', () => {
  let server;
  let baseUrl;

  beforeAll(async () => {
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

  it('allows PATCH in Access-Control-Allow-Methods for browser preflight', async () => {
    const res = await fetch(`${baseUrl}/api/admin/field-mappings/university_roll_number/reorder`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://fillr-v2.netlify.app',
        'Access-Control-Request-Method': 'PATCH',
        'Access-Control-Request-Headers': 'Content-Type, Authorization',
      },
    });

    const allowMethods = res.headers.get('access-control-allow-methods') || '';

    expect(res.status).toBe(200);
    expect(allowMethods.toUpperCase()).toContain('PATCH');
  });
});
