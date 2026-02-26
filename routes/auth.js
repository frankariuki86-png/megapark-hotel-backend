const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const { LoginSchema, RegisterSchema } = require('../validators/schemas');
const { generateTokenPair, refreshAccessToken } = require('../middleware/authenticate');
const { sendWelcomeEmail } = require('../services/emailService');
const { verifyGoogleToken, findOrCreateGoogleUser, sendGoogleWelcomeEmail } = require('../services/googleAuthService');

module.exports = ({ logger, pgClient }) => {
  // Fallback mock user (only used when DB is not configured)
  const mockUsers = [
    { id: 'admin-001', email: 'admin@megapark.com', password: 'admin123', name: 'Admin User', role: 'admin' }
  ];

  const usersFilePath = path.join(__dirname, '..', 'data', 'users.json');

  // Helper to find user by email. If `pgClient` is provided, query the database,
  // otherwise read from `backend/data/users.json` (if present) and fall back to mockUsers.
  const findUserByEmail = async (email) => {
    const lowerEmail = String(email).toLowerCase();
    if (pgClient) {
      try {
        // Wrap query in timeout to prevent hanging on bad connections
        const queryPromise = pgClient.query('SELECT id, email, password_hash AS "passwordHash", name, role FROM users WHERE email = $1 LIMIT 1', [lowerEmail]);
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Database query timeout')), 3000)
        );
        const res = await Promise.race([queryPromise, timeoutPromise]);
        if (res.rows.length === 0) return null;
        return res.rows[0];
      } catch (dbErr) {
        // Fall through to file/mock fallback (don't log, it's expected)
      }
    }

    try {
      const raw = fs.readFileSync(usersFilePath, 'utf8');
      const users = JSON.parse(raw || '[]');
      const u = users.find(x => String(x.email).toLowerCase() === lowerEmail);
      if (u) {
        return {
          id: u.id,
          email: u.email,
          passwordHash: u.passwordHash || u.password_hash || null,
          password: u.password || undefined,
          name: u.name || `${u.firstName || ''} ${u.lastName || ''}`.trim(),
          role: u.role || 'customer'
        };
      }
    } catch (e) {
      // ignore and fallback to mockUsers below
    }

    return mockUsers.find(u => String(u.email).toLowerCase() === lowerEmail) || null;
  };

  router.post('/login', async (req, res) => {
    try {
      const parsed = LoginSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Validation error', details: parsed.error.errors });
      }
      const { email, password } = parsed.data;
      
      const user = await findUserByEmail(email);
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      // For mock users, do direct comparison. For DB users, use bcrypt
      let passwordMatch = false;
      if (user.password) {
        // Mock user - direct comparison
        passwordMatch = (password === user.password);
      } else if (user.passwordHash || user.password_hash) {
        // DB user - use bcrypt
        const hash = user.passwordHash || user.password_hash;
        passwordMatch = await bcrypt.compare(password, hash);
      }

      if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });

      const tokens = generateTokenPair({ id: user.id, email: user.email, role: user.role });
      logger.info({ email: user.email }, 'User logged in');

      return res.json({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: { id: user.id, email: user.email, name: user.name, role: user.role }
      });
    } catch (e) {
      if (e.name === 'ZodError') return res.status(400).json({ error: 'Validation error', details: e.errors });
      logger.error('Login error', e.message || e.toString());
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Register new user
  router.post('/register', async (req, res) => {
    try {
      // Validate input against schema
      const parsed = RegisterSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ 
          error: 'Validation error', 
          details: parsed.error.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
        });
      }

      const { email, password, firstName, lastName, phone } = parsed.data;
      const lowerEmail = email.toLowerCase().trim();

      // If using Postgres
      if (pgClient) {
        try {
          const exists = await pgClient.query('SELECT id FROM users WHERE LOWER(email) = $1 LIMIT 1', [lowerEmail]);
          if (exists.rows.length > 0) {
            return res.status(409).json({ error: 'Account already exists' });
          }

          const passwordHash = await bcrypt.hash(password, 10);
          const id = `user-${Date.now()}`;
          const fullName = `${firstName} ${lastName}`.trim();
          
          await pgClient.query(
            'INSERT INTO users(id, email, password_hash, name, phone, role, is_active, created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
            [id, lowerEmail, passwordHash, fullName, phone || null, 'customer', true, new Date()]
          );

          // Send welcome email
          try {
            await sendWelcomeEmail(lowerEmail, fullName);
          } catch (emailErr) {
            logger.warn(`Welcome email failed for ${lowerEmail}:`, emailErr.message);
            // Don't fail the registration if email fails
          }

          logger.info({ email: lowerEmail }, 'New user registered');
          
          return res.status(201).json({ 
            ok: true, 
            message: 'Account created successfully. A welcome email has been sent.',
            user: { id, email: lowerEmail, name: fullName } 
          });
        } catch (dbErr) {
          logger.error('Database error during registration:', dbErr.message);
          return res.status(500).json({ error: 'Failed to create account' });
        }
      }

      // Fallback to file-based storage in backend/data/users.json
      const usersPath = path.join(__dirname, '..', 'data', 'users.json');
      let users = [];
      try { 
        users = JSON.parse(fs.readFileSync(usersPath, 'utf8')); 
      } catch (e) { 
        users = []; 
      }
      
      if (users.find(u => u.email === lowerEmail)) {
        return res.status(409).json({ error: 'Account already exists' });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const fullName = `${firstName} ${lastName}`.trim();
      const newUser = { 
        id: `user-${Date.now()}`, 
        email: lowerEmail, 
        passwordHash, 
        name: fullName, 
        phone: phone || null, 
        role: 'customer', 
        createdAt: new Date().toISOString() 
      };
      users.push(newUser);
      fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));

      // Send welcome email
      try {
        await sendWelcomeEmail(lowerEmail, fullName);
      } catch (emailErr) {
        logger.warn(`Welcome email failed for ${lowerEmail}:`, emailErr.message);
        // Don't fail the registration if email fails
      }

      logger.info({ email: lowerEmail }, 'New user registered (file-based)');

      return res.status(201).json({ 
        ok: true,
        message: 'Account created successfully. A welcome email has been sent.',
        user: { id: newUser.id, email: newUser.email, name: newUser.name } 
      });
    } catch (e) {
      logger.error('Register error', e.message || e.toString());
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Refresh endpoint — accepts a refresh token and returns a new token pair
  router.post('/refresh', async (req, res) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
      const tokens = refreshAccessToken(refreshToken);
      logger.info({}, 'Token refreshed');
      return res.json({ accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });
    } catch (e) {
      logger.error('Token refresh error', e.message || e.toString());
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
  });

  // Logout endpoint (stateless; client should clear tokens)
  router.post('/logout', (req, res) => {
    logger.info({}, 'User logged out');
    return res.json({ message: 'Logged out successfully' });
  });

  // Google OAuth login endpoint
  router.post('/google', async (req, res) => {
    try {
      const { idToken } = req.body;
      if (!idToken) {
        return res.status(400).json({ error: 'ID token required' });
      }

      // Verify Google token
      const googleData = await verifyGoogleToken(idToken);
      logger.info({ email: googleData.email }, 'Google token verified');

      // Find or create user
      const user = await findOrCreateGoogleUser(googleData, pgClient, logger);

      // Generate JWT tokens
      const tokens = generateTokenPair({ 
        id: user.id, 
        email: user.email, 
        role: user.role || 'customer' 
      });

      // Send welcome email to new users
      if (user.created_at && new Date(user.created_at) > new Date(Date.now() - 60000)) {
        // User created less than 60 seconds ago (new user)
        const { sendEmail } = require('../services/emailService');
        await sendGoogleWelcomeEmail(
          user.email,
          user.name || 'User',
          sendEmail
        );
      }

      logger.info({ email: user.email }, 'User authenticated via Google');
      
      return res.json({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
          role: user.role || 'customer',
          picture: googleData.picture
        }
      });
    } catch (err) {
      logger.error('Google authentication failed', err.message || err.toString());
      return res.status(401).json({ error: err.message || 'Google authentication failed' });
    }
  });

  return router;
};
