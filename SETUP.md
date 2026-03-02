# Fillr Environment Setup Guide

## 🎯 Overview

Fillr uses environment-specific configuration files to keep sensitive data (API keys, URLs) out of version control. This guide shows you how to set up your development environment.

## 📁 Environment Files

### Backend (Server)
- **File**: `server/.env`
- **Template**: Create manually
- **Contains**: Database credentials, JWT secret, API keys

### Frontend (Client)
- **File**: `client/env.js`
- **Template**: `client/env.example.js`
- **Contains**: API URL, Google Client ID

### Extension
- **File**: `extension/env.js`
- **Template**: `extension/env.example.js`
- **Contains**: Backend API URL

## ⚡ Quick Setup

### Automated (Recommended)

**Windows (PowerShell):**
```powershell
.\setup-env.ps1
```

**Linux/Mac:**
```bash
chmod +x setup-env.sh
./setup-env.sh
```

### Manual Setup

```bash
# Frontend
cp client/env.example.js client/env.js

# Extension
cp extension/env.example.js extension/env.js

# Server (create manually)
# Use template below
```

## 📝 Configuration Templates

### 1. Frontend (`client/env.js`)

```javascript
const ENV = Object.freeze({
  // Development
  API_URL: 'http://localhost:5000/api',
  
  // Production
  // API_URL: 'https://fillrv2.onrender.com/api',
  
  // Google OAuth Client ID
  GOOGLE_CLIENT_ID: 'your-google-client-id.apps.googleusercontent.com',
});
```

### 2. Extension (`extension/env.js`)

```javascript
var ENV = Object.freeze({
  // Development
  API_URL: 'http://localhost:5000',
  
  // Production
  // API_URL: 'https://fillrv2.onrender.com',
});
```

### 3. Server (`server/.env`)

```env
# Server
PORT=5000
NODE_ENV=development

# Database
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/fillr

# Authentication
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters
GOOGLE_CLIENT_ID=your-google-oauth-client-id.apps.googleusercontent.com

# CORS (comma-separated, no spaces)
# Add your frontend URL to allowed origins
CORS_ORIGINS=http://127.0.0.1:5500,http://localhost:3000,https://fillr-v2.netlify.app

# Email (Resend)
RESEND_API_KEY=re_your_resend_api_key
RESEND_FROM=Fillr <noreply@yourdomain.com>

# Frontend URL (for password reset emails)
# Development: http://127.0.0.1:5500
# Production: https://fillr-v2.netlify.app
FRONTEND_URL=http://127.0.0.1:5500

# Chrome Extension ID (leave blank in dev)
EXTENSION_ID=
```

## 🔒 Security Best Practices

### ✅ DO:
- ✅ Copy from `.example` files
- ✅ Use different values for dev/staging/prod
- ✅ Keep credentials in environment files only
- ✅ Add `env.js` to `.gitignore`
- ✅ Generate strong, unique JWT secrets

### ❌ DON'T:
- ❌ Commit `env.js` or `.env` files
- ❌ Share credentials in chat/email
- ❌ Use production credentials in development
- ❌ Hardcode secrets in source code
- ❌ Reuse JWT secrets across projects

## 🔑 Getting Credentials

### MongoDB Atlas
1. Visit [mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)
2. Create free cluster
3. Get connection string from **Connect** → **Connect your application**
4. Format: `mongodb+srv://user:pass@cluster.mongodb.net/dbname`

### Google OAuth Client ID
1. Visit [console.cloud.google.com](https://console.cloud.google.com)
2. Create project or select existing
3. Go to **APIs & Services** → **Credentials**
4. **Create OAuth 2.0 Client ID**
5. Add authorized origins: `http://localhost:5500`, `http://127.0.0.1:5500`
6. Copy Client ID

### Resend API Key (Email)
1. Visit [resend.com](https://resend.com)
2. Sign up / Log in
3. **API Keys** → **Create API Key**
4. Copy key (starts with `re_`)
5. Verify your domain for production

### JWT Secret
Generate a secure random string:

**PowerShell:**
```powershell
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 64 | ForEach-Object {[char]$_})
```

**Linux/Mac:**
```bash
openssl rand -hex 32
```

## 🚀 Starting the Application

### 1. Backend
```bash
cd server
npm install
npm run dev
```

Server: `http://localhost:5000`

### 2. Frontend
```bash
cd client
# VS Code: Right-click index.html → Open with Live Server
# OR use: npx http-server -p 3000
```

Frontend: `http://127.0.0.1:5500/pages/` or `http://localhost:3000/pages/`

### 3. Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. **Load unpacked** → Select `extension/` folder
4. Pin extension to toolbar

## 🐛 Troubleshooting

### "ENV is not defined"
- ✅ Make sure `env.js` exists (not just `.example`)
- ✅ Check HTML includes: `<script src="../env.js"></script>`
- ✅ Verify file is loaded before other scripts

### "API Connection Failed"
- ✅ Backend server is running (`npm run dev`)
- ✅ API_URL in `env.js` matches server port
- ✅ No typos in URL (trailing slashes, http vs https)
- ✅ CORS_ORIGINS in server `.env` includes frontend URL

### "Google Sign-In Not Working"
- ✅ GOOGLE_CLIENT_ID matches in:
  - `server/.env`
  - `client/env.js`
- ✅ Authorized origins added in Google Console
- ✅ Client ID is valid and not expired

### "Extension Not Autofilling"
- ✅ Extension has `env.js` configured
- ✅ API_URL points to running backend
- ✅ User is logged in (click extension icon)
- ✅ Extension key generated from dashboard
- ✅ Check console for errors (F12)

## 📚 Additional Resources

- **Full Documentation**: See [README.md](README.md)
- **API Endpoints**: See README → API Endpoints section
- **Deployment**: See README → Deployment section

## 💡 Tips

- Use VS Code **Live Server** extension for instant frontend reload
- Keep terminal windows for backend/frontend side-by-side
- Use Chrome DevTools (F12) to debug extension
- Check `server/src/services/logger.js` for backend logs

---

**Need Help?** Open an issue at [github.com/Kartiik7/Fillrv2/issues](https://github.com/Kartiik7/Fillrv2/issues)
