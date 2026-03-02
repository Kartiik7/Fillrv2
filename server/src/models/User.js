const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

/**
 * ROLES — Single source of truth for role values.
 * Import this constant anywhere role-checking is needed.
 * To add a new role (e.g. 'moderator', 'superadmin'):
 *  1. Add the key/value here.
 *  2. Add the value to the schema enum below.
 *  3. Add guard logic in adminMiddleware or a new roleMiddleware.
 */
const ROLES = Object.freeze({
  USER:  'user',
  ADMIN: 'admin',
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: false },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: false }, // Optional for Google OAuth users
  // ── Authentication provider ───────────────────────────────
  // Tracks how the user registered — prevents password-less users from
  // authenticating via the email/password flow.
  // Backward compatible — existing users default to 'local'.
  authProvider: { type: String, enum: ['local', 'google'], default: 'local' },
  googleId:     { type: String, default: null }, // Google OAuth sub — index defined below
  displayName:  { type: String, default: '' }, // Name from Google profile
  // ── Role-based access control ─────────────────────────────
  // Default ROLES.USER for all registrations. Admin is set ONLY via
  // admin-authenticated PATCH /api/admin/users/:id/role.
  // No public API endpoint may set or update this field.
  role: {
    type:    String,
    enum:    Object.values(ROLES), // ['user', 'admin'] — extend ROLES to add more
    default: ROLES.USER,
  },
  // ── Account suspension ────────────────────────────────────
  // When true: blocks login, Google auth, and extension auth.
  // Toggled ONLY by admin via PATCH /api/admin/users/:id/suspend.
  isSuspended: {
    type:    Boolean,
    default: false,
  },
  profile: {
    personal: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        name: '',
        email: '',
        phone: '',
        gender: '',
        dob: '',
        age: '',
        permanent_address: '',
      },
    },
    academics: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        tenth_percentage: '',
        twelfth_percentage: '',
        diploma_percentage: '',
        cgpa: '',
        graduation_percentage: '',
        pg_percentage: '',
        active_backlog: 'No',
        backlog_count: '0',
        gap_months: '0',
      },
    },
    ids: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        uid: '',
        roll_number: '',
        university_roll_number: '',
      },
    },
    links: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        github: '',
        linkedin: '',
        portfolio: '',
        resume: '',
      },
    },
    education: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        college_name: '',
        batch: '',
        program: '',
        stream: '',
      },
    },
    placement: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        position_applying: '',
        job_location: '',
      },
    },
  },
  // ── Legal consent (required for GDPR / SaaS compliance) ──
  // termsAccepted is enforced at registration — no bypass allowed.
  // Versioning fields allow re-prompting users if policies are updated.
  // Backward compatibility: defaults allow existing users to keep working.
  termsAccepted:    { type: Boolean, default: false },
  termsAcceptedAt:  { type: Date,    default: null  },
  termsVersion:     { type: String,  default: ''    }, // e.g. "1.0"
  privacyVersion:   { type: String,  default: ''    }, // e.g. "1.0"
  // ── Password reset (secure, single-use) ───────────────────
  // Raw token is NEVER stored — only a SHA-256 hash.
  // Expiry is 30 minutes from generation.
  // Both fields are cleared immediately after a successful reset.
  resetPasswordHash:   { type: String,  default: null, select: false },
  resetPasswordExpiry: { type: Date,    default: null, select: false },
  // ── Email verification ────────────────────────────────────
  // isVerified gates login for email/password users.
  // Google OAuth users are auto-verified (Google verifies their email).
  // Token is SHA-256 hashed (same pattern as password reset).
  isVerified:              { type: Boolean, default: false },
  verificationTokenHash:   { type: String,  default: null, select: false },
  verificationTokenExpiry: { type: Date,    default: null, select: false },
}, { timestamps: true });

// ── Indexes ───────────────────────────────────────────────────
// googleId index is sparse — only Google OAuth users have this field.
// Prevents duplicate googleId while allowing null for local users.
userSchema.index({ googleId: 1 }, { unique: true, sparse: true });

// email — unique, most-queried field (login, forgot-password, resend-verification)
// Defined as unique in the schema field options, but an explicit index
// improves clarity and allows partial index in future.
userSchema.index({ email: 1 }, { unique: true });

// isSuspended — admin user listing filters by suspension status
userSchema.index({ isSuspended: 1 });

// createdAt — admin user listing sorts newest-first
userSchema.index({ createdAt: -1 });

// verificationTokenHash — sparse, only set on unverified accounts
userSchema.index({ verificationTokenHash: 1 }, { sparse: true });

// resetPasswordHash — sparse, only set during active reset flow
userSchema.index({ resetPasswordHash: 1 }, { sparse: true });

// Encrypt password using bcrypt — only for local auth users
userSchema.pre('save', async function () {
  if (!this.isModified('password') || !this.password) {
    return;
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (enteredPassword) {
  if (!this.password) return false; // Google OAuth users have no password
  return await bcrypt.compare(enteredPassword, this.password);
};

const UserModel = mongoose.model('User', userSchema);

// Export both — ROLES is used by middleware and admin routes
module.exports        = UserModel;
module.exports.ROLES  = ROLES;
