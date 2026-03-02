# Fillr v2.0 – Placement Form Autofill

> **Intelligent Chrome extension that automatically fills placement and recruitment forms with your saved profile data.**

Fillr reads your academic profile once and autofills every placement registration form — percentages, dropdowns, radios — in a single click. Powered by weighted keyword matching, confidence scoring, and dynamic field mapping.

[![Version](https://img.shields.io/badge/version-2.0.0--beta-blue.svg)](https://github.com/Kartiik7/Fillrv2)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-green.svg)](https://github.com/Kartiik7/Fillrv2)
[![License](https://img.shields.io/badge/license-ISC-orange.svg)](LICENSE)

---

## 🚀 Features

### For Students
- **One-Click Autofill**: Fill entire forms instantly with intelligent field matching
- **Dynamic Field Mapping**: Adapts to any form structure using keyword-based matching
- **Multi-Format Support**: Works with Google Forms and standard HTML forms
- **Profile Management**: Centralized dashboard to manage all your academic data
- **Field Types**: Supports text, number, date, email, tel, URL, textarea, and select inputs
- **Auto-Calculations**: Automatic age calculation from date of birth
- **Smart Matching**: Weighted keyword algorithm with confidence scoring
- **Secure Storage**: JWT-based authentication with encrypted data storage

### For Admins
- **Field Mapping Management**: Create and manage custom field mappings via admin panel
- **User Management**: View user statistics, audit logs, and system metrics
- **Version Control**: Track configuration versions with automatic updates
- **API Keys**: Generate extension keys for secure access
- **Real-time Sync**: Instant configuration updates across all users

---

## 🛠️ Tech Stack

### Backend
- **Node.js** + **Express.js** – REST API server
- **MongoDB** + **Mongoose** – Database and ODM
- **JWT** – Authentication
- **Joi** – Schema validation
- **Helmet** + **CORS** – Security
- **Rate Limiting** – DDoS protection
- **Resend** – Email service (password reset)

### Frontend
- **Vanilla JavaScript** – No framework dependencies
- **HTML5** + **CSS3** – Responsive design
- **Fetch API** – HTTP client
- **LocalStorage** – Client-side caching

### Chrome Extension
- **Manifest V3** – Latest Chrome extension standard
- **Content Scripts** – DOM manipulation
- **Service Worker** – Background processing
- **Chrome Storage API** – Settings persistence

### Deployment
- **Netlify** – Static site hosting (client)
- **MongoDB Atlas** – Cloud database
- **Environment Variables** – Configuration management

---

## 📁 Project Structure

```
Fillr/
├── client/                  # Frontend web application
│   ├── pages/              # HTML pages (dashboard, admin, auth)
│   ├── css/                # Stylesheets (modular design)
│   ├── js/                 # JavaScript modules (API, field mappings)
│   └── assets/             # Images, icons, favicon
│
├── extension/              # Chrome extension
│   ├── manifest.json       # Extension configuration
│   ├── popup.html          # Extension popup UI
│   ├── popup.js            # Popup logic
│   ├── background.js       # Service worker
│   ├── content.js          # Form autofill logic
│   ├── matcher.js          # Keyword matching algorithm
│   ├── env.js              # Environment config
│   └── icons/              # Extension icons
│
├── server/                 # Backend API server
│   ├── server.js           # Entry point
│   ├── src/
│   │   ├── app.js          # Express app configuration
│   │   ├── config/         # Database and configuration
│   │   ├── controllers/    # Request handlers
│   │   ├── middleware/     # Auth, admin middleware
│   │   ├── models/         # Mongoose schemas
│   │   ├── routes/         # API routes
│   │   ├── services/       # Business logic (audit, metrics, logger)
│   │   └── tests/          # Jest unit tests
│   ├── package.json
│   └── .env                # Environment variables
│
├── netlify.toml            # Netlify deployment config
└── README.md               # This file
```

---

## 🔧 Installation & Setup

### Prerequisites
- **Node.js** v16+ and npm
- **MongoDB** instance (local or Atlas)
- **Chrome Browser** (for extension testing)
- **Resend API Key** (for email features)

### 1. Clone Repository
```bash
git clone https://github.com/Kartiik7/Fillrv2.git
cd Fillrv2
```

### 2. Quick Setup (Environment Files)

**Automated Setup (Recommended):**

Windows (PowerShell):
```powershell
.\setup-env.ps1
```

Linux/Mac:
```bash
chmod +x setup-env.sh
./setup-env.sh
```

This creates:
- `client/env.js` from `client/env.example.js`
- `extension/env.js` from `extension/env.example.js`

**Manual Setup:**
```bash
# Frontend
cp client/env.example.js client/env.js

# Extension
cp extension/env.example.js extension/env.js
```

Then edit each file with your configuration.

### 3. Backend Setup

#### Install Dependencies
```bash
cd server
npm install
```

#### Configure Environment Variables
Create a `.env` file in the `server/` directory:

```env
PORT=5000
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/fillr
JWT_SECRET=your-super-secret-jwt-key-here
GOOGLE_CLIENT_ID=your-google-oauth-client-id

# CORS Origins (comma-separated, no spaces)
CORS_ORIGINS=http://127.0.0.1:5500,http://localhost:3000,https://fillr-v2.netlify.app

# Email Service (Resend)
RESEND_API_KEY=your-resend-api-key
RESEND_FROM=Fillr <noreply@yourdomain.com>

# Frontend URL (for password reset links)
FRONTEND_URL=https://fillr-v2.netlify.app

# Environment
NODE_ENV=production

# Chrome Extension ID (leave blank in dev)
EXTENSION_ID=
```

#### Start Server
```bash
# Development mode (auto-reload)
npm run dev

# Production mode
npm start
```

Server runs at: **http://localhost:5000**

### 4. Frontend Setup

#### Option A: Live Server (VS Code)
1. Install **Live Server** extension in VS Code
2. Right-click `client/pages/index.html` → **Open with Live Server**
3. Access at: **http://127.0.0.1:5500/pages/index.html**

#### Option B: Static Server
```bash
cd client
npx http-server -p 3000
```

Access at: **http://localhost:3000/pages/index.html**

#### Configure Frontend Environment
Create `client/env.js` from the example:
```bash
cd client
cp env.example.js env.js
```

Edit `client/env.js` with your values:
```javascript
const ENV = Object.freeze({
  API_URL: 'http://localhost:5000/api',
  GOOGLE_CLIENT_ID: 'your-google-client-id.apps.googleusercontent.com',
});
```

### 5. Extension Setup

#### Configure Extension Environment
Create `extension/env.js` from the example:
```bash
cd extension
cp env.example.js env.js
```

Edit `extension/env.js` with your backend URL:
```javascript
var ENV = Object.freeze({
  API_URL: 'http://localhost:5000',
});
```

#### Load Unpacked Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Extension icon appears in toolbar

---

## 📖 Usage

### For Students

#### 1. **Register Account**
- Visit landing page → Click **Get started**
- Fill registration form → Verify email
- Login with credentials

#### 2. **Complete Profile**
- Access **Dashboard** after login
- Fill out profile sections:
  - **Identity**: UID, Roll numbers
  - **Personal**: Name, email, phone, DOB
  - **Academic**: Marks, CGPA, percentages
  - **Education**: Degrees, institutions
  - **Placement**: Skills, resume link
  - **Links**: Portfolio, GitHub, LinkedIn
- Click **Save Profile**

#### 3. **Use Extension**
- Install Chrome extension
- Open any Google Form or HTML form
- Click extension icon → **Autofill**
- Review filled data → Submit form

#### 4. **Fetch Latest Fields**
- Click **Fetch latest fields** button in dashboard toolbar
- Updates appear when admin adds new field mappings

### For Admins

#### 1. **Access Admin Panel**
- Login with admin credentials
- Visit `/admin` route
- View metrics, users, audit logs

#### 2. **Manage Field Mappings**
- Click **Field Mappings** card
- Add new mapping:
  - **Key**: Database field name (e.g., `personal.name`)
  - **Path**: Group prefix (e.g., `personal`)
  - **Type**: Field type (text, number, date, etc.)
  - **Keywords**: Primary, secondary, generic, negative
- Edit/delete existing mappings
- Version auto-increments on changes

#### 3. **Monitor System**
- View active users, field mapping count
- Check recent admin activity (audit logs)
- Debug field mappings with preview tool

---

## 🔌 API Endpoints

### Public Routes
```http
# Configuration
GET  /api/config/full          # All field mappings + metadata
GET  /api/config/field-mappings # Field mappings only
GET  /api/config/version       # Current config version
GET  /api/config/meta          # Aggregate metadata (last update)

# Authentication
POST /api/auth/register        # Create account
POST /api/auth/login           # Login (JWT token)
POST /api/auth/google-auth     # Google OAuth login
POST /api/auth/verify-email    # Verify email with token
POST /api/auth/forgot-password # Request password reset
POST /api/auth/reset-password  # Reset password with token
```

### Protected Routes (Requires JWT)
```http
# Profile Management
GET    /api/profile            # Get user profile
PUT    /api/profile            # Update profile (dynamic fields)
DELETE /api/profile            # Delete account

# Extension Keys
GET    /api/keys               # List user's API keys
POST   /api/keys               # Generate new key
DELETE /api/keys/:id           # Revoke key
```

### Admin Routes (Requires Admin JWT)
```http
# Field Mappings
GET    /api/admin/field-mappings        # List all mappings
POST   /api/admin/field-mappings        # Create mapping
PUT    /api/admin/field-mappings/:id    # Update mapping
DELETE /api/admin/field-mappings/:id    # Delete mapping

# User Management
GET    /api/admin/users                 # List users
GET    /api/admin/users/stats           # User statistics

# System
GET    /api/admin/metrics               # System metrics
GET    /api/admin/audit-logs            # Audit log entries
POST   /api/admin/audit-logs            # Create audit entry
GET    /api/admin/config/version        # Config version info
```

---

## ⚙️ Configuration

### Field Mapping Schema
```javascript
{
  "key": "personal.name",           // Database path
  "path": "personal",               // Group prefix
  "fieldType": "text",              // Field input type
  "keywords": {
    "primary": ["name", "fullname"],
    "secondary": ["student"],
    "generic": ["your"],
    "negative": ["father", "mother"]
  }
}
```

### Field Types
- `text` – Single-line text input
- `number` – Numeric input
- `date` – Date picker
- `email` – Email validation
- `tel` – Phone number
- `url` – URL validation
- `textarea` – Multi-line text
- `select` – Dropdown/select

### Keyword Matching Weights
- **Primary**: 100 points (exact match)
- **Secondary**: 50 points (context)
- **Generic**: 10 points (filler words)
- **Negative**: -200 points (exclusion)

**Confidence Threshold**: 60 points minimum

---

## 🧪 Development

### Run Tests
```bash
cd server
npm test              # Run all tests
npm run test:watch    # Watch mode
```

### Code Structure

#### Middleware
- **authMiddleware.js**: JWT verification
- **adminMiddleware.js**: Admin role check

#### Models
- **User.js**: User schema with dynamic profile (Mixed type)
- **FieldMapping.js**: Field mapping configuration
- **ConfigVersion.js**: Version tracking (singleton)
- **ExtensionKey.js**: API key management
- **AuditLog.js**: Admin action logging
- **SystemMetric.js**: System performance metrics

#### Controllers
- **authController.js**: Registration, login, OAuth
- **profileController.js**: Dynamic profile CRUD with injection protection
- **keyController.js**: API key generation
- **resetController.js**: Password reset flow
- **verificationController.js**: Email verification
- **userController.js**: User management

#### Services
- **logger.js**: Winston logger (file + console)
- **auditService.js**: Admin activity tracking
- **metricsService.js**: System metrics collection

---

## 🚀 Deployment

### Production URLs
- **Frontend**: https://fillr-v2.netlify.app
- **Backend API**: https://fillrv2.onrender.com

### Backend (Node.js on Render)
**Current Setup**: Backend deployed on [Render](https://render.com)

1. **Environment**: Set `NODE_ENV=production` in Render dashboard
2. **Database**: MongoDB Atlas connection string in environment variables
3. **Environment Variables**: Configure in Render dashboard:
   - `MONGO_URI`
   - `JWT_SECRET`
   - `GOOGLE_CLIENT_ID`
   - `CORS_ORIGINS=https://fillr-v2.netlify.app`
   - `FRONTEND_URL=https://fillr-v2.netlify.app`
   - `RESEND_API_KEY`
   - `RESEND_FROM`
   - `NODE_ENV=production`

**Deploy Updates**:
```bash
git push origin main  # Render auto-deploys from GitHub
```

**Alternative Platforms**: Railway, Heroku, DigitalOcean, AWS EC2

### Frontend (Static on Netlify)
**Current Setup**: Frontend deployed on [Netlify](https://netlify.com)

1. **Configuration**: Already configured in `netlify.toml`
2. **Deploy**:
   ```bash
   git push origin main  # Netlify auto-deploys from GitHub
   ```
3. **Features**:
   - Automatic deployment from GitHub
   - Clean URLs configured
   - Security headers enabled
   - HTTPS by default

**Alternative Platforms**: Vercel, GitHub Pages, Cloudflare Pages

### Chrome Extension

#### Build Extension Package
Use the automated build script to create the distribution ZIP:

**Windows (PowerShell):**
```powershell
.\build-extension.ps1
```

**Linux/Mac (Bash):**
```bash
chmod +x build-extension.sh
./build-extension.sh
```

This creates `fillr-extension-v2.0.0-beta.zip` in the project root.

#### Upload to GitHub Releases
1. Go to repository **Releases** → **Create a new release**
2. Tag: `v2.0.0-beta`
3. Title: `Fillr Extension v2.0.0 Beta`
4. Upload the generated ZIP file
5. Publish release

#### Submit to Chrome Web Store (Optional)
1. Visit [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Upload `fillr-extension-v2.0.0-beta.zip`
3. Complete store listing
4. Submit for review (3-7 days)

---

## 🔒 Security Features

- **JWT Authentication**: Secure token-based auth
- **Password Hashing**: bcrypt with salt rounds
- **Rate Limiting**: 60 requests per 15 minutes
- **Input Sanitization**: MongoDB injection protection
- **Helmet.js**: HTTP security headers
- **CORS**: Whitelist-based origin control
- **Prototype Pollution**: Protection via `sanitizeObject()`
- **XSS Prevention**: Content Security Policy

---

## 📝 Environment Variables Reference

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PORT` | Server port | No | `5000` |
| `MONGO_URI` | MongoDB connection string | Yes | - |
| `JWT_SECRET` | Secret key for JWT signing | Yes | - |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | No | - |
| `CORS_ORIGINS` | Allowed origins (comma-separated) | Yes | - |
| `RESEND_API_KEY` | Resend email API key | No | - |
| `RESEND_FROM` | Email sender address | No | - |
| `FRONTEND_URL` | Frontend base URL | Yes | - |
| `NODE_ENV` | Environment mode | No | `development` |
| `EXTENSION_ID` | Chrome extension ID | No | - |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **ISC License**.

---

## 👨‍💻 Author

**Kartik Patel**
- GitHub: [@Kartiik7](https://github.com/Kartiik7)
- Repository: [Fillrv2](https://github.com/Kartiik7/Fillrv2)

---

## 🆘 Support

If you encounter any issues or have questions:

1. Check existing [Issues](https://github.com/Kartiik7/Fillrv2/issues)
2. Open a new issue with detailed description
3. Include error logs and environment details

---

## 🎯 Roadmap

### v2.1 (Upcoming)
- [ ] Bulk user import (CSV)
- [ ] Multi-language support
- [ ] Mobile app (React Native)
- [ ] Advanced analytics dashboard
- [ ] Browser extension (Firefox, Edge)

### v2.2
- [ ] AI-powered field matching
- [ ] Form templates/presets
- [ ] Team collaboration features
- [ ] Export profile as PDF/JSON

---

## 🙏 Acknowledgments

- **MongoDB Atlas** – Database hosting
- **Netlify** – Frontend hosting
- **Resend** – Email service
- **Google Fonts** – Inter & JetBrains Mono typography
- **Chrome Extension APIs** – Browser integration

---

<div align="center">

**⭐ Star this repo if Fillr saved you time!**

Made with ❤️ for students tired of filling the same forms

</div>
