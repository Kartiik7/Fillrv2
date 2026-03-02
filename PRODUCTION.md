# Fillr v2 - Production Configuration

## 🌐 Live URLs

### Frontend (Netlify)
- **URL**: https://fillr-v2.netlify.app
- **Platform**: Netlify
- **Deployment**: Auto-deploy from GitHub (main branch)

### Backend API (Render)
- **URL**: https://fillrv2.onrender.com
- **API Base**: https://fillrv2.onrender.com/api
- **Platform**: Render
- **Deployment**: Auto-deploy from GitHub (main branch)

### Extension
- **Version**: 2.0.0-beta
- **Status**: Build locally, upload to Chrome Web Store or GitHub Releases

---

## ⚙️ Current Configuration

### Client (`client/env.js`)
```javascript
const ENV = Object.freeze({
  API_URL: 'https://fillrv2.onrender.com/api',
  GOOGLE_CLIENT_ID: '555611983522-phrlkcadl138k2qe1oq27j3dhtuqliev.apps.googleusercontent.com',
});
```

### Extension (`extension/env.js`)
```javascript
var ENV = Object.freeze({
  API_URL: 'https://fillrv2.onrender.com',
});
```

### Server (`server/.env`)
```env
PORT=5000
NODE_ENV=production
MONGO_URI=mongodb+srv://fillrAppUser:***@firstcluster.y7uibfa.mongodb.net/
JWT_SECRET=***
GOOGLE_CLIENT_ID=555611983522-phrlkcadl138k2qe1oq27j3dhtuqliev.apps.googleusercontent.com
CORS_ORIGINS=http://127.0.0.1:5500,http://localhost:3000,https://fillr-v2.netlify.app
RESEND_API_KEY=re_***
RESEND_FROM=Fillr <noreply@passwordreset.fillr.kartikpatel.tech>
FRONTEND_URL=https://fillr-v2.netlify.app
EXTENSION_ID=
```

---

## 🔄 Deployment Workflow

### Making Changes

1. **Code Changes**
   ```bash
   git add .
   git commit -m "Your changes"
   git push origin main
   ```

2. **Automatic Deployments**
   - **Netlify** (Frontend): Deploys automatically in ~1-2 minutes
   - **Render** (Backend): Deploys automatically in ~2-5 minutes

3. **Extension Updates**
   ```powershell
   # Build new package
   .\build-extension.ps1
   
   # Upload to:
   # - Chrome Web Store (for public release)
   # - GitHub Releases (for distribution)
   ```

### Monitoring

- **Frontend Status**: https://app.netlify.com/teams/[your-team]/sites
- **Backend Status**: https://dashboard.render.com/
- **Backend Logs**: Check Render dashboard → Logs tab
- **Frontend Logs**: Check Netlify dashboard → Deploys → Deploy log

---

## 🔍 Testing Production

### Test Frontend
```bash
# Visit
https://fillr-v2.netlify.app

# Should load landing page
```

### Test Backend API
```bash
# Health check (if you have one)
curl https://fillrv2.onrender.com/api/health

# Or test login endpoint
curl -X POST https://fillrv2.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test"}'
```

### Test Extension
1. Load extension in Chrome (chrome://extensions/)
2. Click extension icon
3. Should connect to production backend
4. Test autofill on a Google Form

---

## 🐛 Common Issues

### Extension Not Connecting
**Problem**: Extension can't reach backend API

**Solution**:
1. Verify `extension/env.js` has correct URL
2. Check `extension/manifest.json` includes Render URL in `host_permissions`
3. Reload extension in chrome://extensions/

### CORS Errors
**Problem**: Frontend can't call backend API

**Solution**:
1. Check Render environment variable `CORS_ORIGINS` includes `https://fillr-v2.netlify.app`
2. Restart backend service on Render
3. Clear browser cache

### Password Reset Emails Not Sending
**Problem**: Users not receiving password reset emails

**Solution**:
1. Check Render environment variable `FRONTEND_URL=https://fillr-v2.netlify.app`
2. Verify `RESEND_API_KEY` is valid
3. Check Resend dashboard for delivery status

### Backend Cold Starts (Render Free Tier)
**Problem**: First request after inactivity is slow

**Why**: Render free tier spins down after 15 minutes of inactivity

**Solution**:
- Upgrade to paid tier for always-on instances
- Or accept 30-60 second cold start delay

---

## 🔐 Security Checklist

- ✅ HTTPS enabled on both frontend and backend
- ✅ CORS origins restricted to production domain
- ✅ Environment variables not committed to Git
- ✅ JWT secret is strong and unique
- ✅ MongoDB credentials secured in environment variables
- ✅ Google OAuth credentials configured correctly
- ✅ Security headers configured in netlify.toml

---

## 📊 Performance

### Netlify (CDN-backed)
- **TTFB**: ~50-100ms (with CDN cache)
- **Global**: CDN edges worldwide
- **Uptime**: 99.9%+

### Render (Backend)
- **Response Time**: ~200-500ms (depending on region)
- **Cold Start**: 30-60 seconds (free tier)
- **Region**: Auto-selected by Render

---

## 📝 Environment Variables Reference

### Required in Render Dashboard
| Variable | Example | Purpose |
|----------|---------|---------|
| `MONGO_URI` | `mongodb+srv://...` | Database connection |
| `JWT_SECRET` | `your-secret-key` | Token signing |
| `GOOGLE_CLIENT_ID` | `*.apps.googleusercontent.com` | OAuth |
| `CORS_ORIGINS` | `https://fillr-v2.netlify.app` | CORS whitelist |
| `FRONTEND_URL` | `https://fillr-v2.netlify.app` | Reset links |
| `RESEND_API_KEY` | `re_*` | Email service |
| `RESEND_FROM` | `Fillr <no-reply@...>` | Email sender |
| `NODE_ENV` | `production` | Environment |

---

## 🔄 Rollback Procedure

### Frontend (Netlify)
1. Go to Netlify dashboard → Deploys
2. Find previous working deploy
3. Click "..." → "Publish deploy"

### Backend (Render)
1. Go to Render dashboard → Service
2. Click "Manual Deploy" → Select previous commit
3. Or: `git revert HEAD` and push

---

## 📈 Next Steps

- [ ] Set up custom domain (if needed)
- [ ] Configure monitoring/alerts
- [ ] Set up automated backups for MongoDB
- [ ] Submit extension to Chrome Web Store
- [ ] Add analytics (optional)
- [ ] Set up error tracking (Sentry, etc.)

---

**Last Updated**: March 2, 2026  
**Version**: 2.0.0-beta
