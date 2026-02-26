const { OAuth2Client } = require('google-auth-library');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

module.exports = {
  /**
   * Verify Google ID token and extract user info
   */
  verifyGoogleToken: async (token) => {
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      return {
        id: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
        givenName: payload.given_name,
        familyName: payload.family_name,
      };
    } catch (err) {
      throw new Error(`Invalid Google token: ${err.message}`);
    }
  },

  /**
   * Find or create user from Google account
   * Stores in database if available, otherwise in JSON file
   */
  findOrCreateGoogleUser: async (googleData, pgClient, logger) => {
    const lowerEmail = googleData.email.toLowerCase();
    const usersFilePath = path.join(__dirname, '..', 'data', 'users.json');

    // Try database first
    if (pgClient) {
      try {
        // Check if user exists
        const existing = await pgClient.query(
          'SELECT id, email, name, role, created_at FROM users WHERE email = $1 LIMIT 1',
          [lowerEmail]
        );

        if (existing.rows.length > 0) {
          logger.info({ email: lowerEmail }, 'Existing Google user logged in');
          return existing.rows[0];
        }

        // Create new user
        const id = `google-${googleData.id}`;
        const firstName = googleData.givenName || googleData.name.split(' ')[0];
        const lastName = googleData.familyName || googleData.name.split(' ').slice(1).join(' ') || '';

        await pgClient.query(
          `INSERT INTO users (id, email, name, role, created_at, updated_at)
           VALUES ($1, $2, $3, $4, NOW(), NOW())
           ON CONFLICT (email) DO NOTHING`,
          [id, lowerEmail, googleData.name, 'customer']
        );

        logger.info({ email: lowerEmail }, 'New Google user created');
        return {
          id,
          email: lowerEmail,
          name: googleData.name,
          role: 'customer',
          created_at: new Date().toISOString(),
        };
      } catch (dbErr) {
        logger.warn('Database not available, using file fallback:', dbErr.message);
        // Fall through to file storage
      }
    }

    // File-based storage fallback
    try {
      let users = [];
      if (fs.existsSync(usersFilePath)) {
        const data = fs.readFileSync(usersFilePath, 'utf8');
        users = JSON.parse(data || '[]');
      }

      const existing = users.find(u => String(u.email).toLowerCase() === lowerEmail);
      if (existing) {
        logger.info({ email: lowerEmail }, 'Existing Google user logged in (file)');
        return existing;
      }

      // Create new user
      const newUser = {
        id: `google-${googleData.id}`,
        email: lowerEmail,
        name: googleData.name,
        firstName: googleData.givenName || googleData.name.split(' ')[0],
        lastName: googleData.familyName || googleData.name.split(' ').slice(1).join(' ') || '',
        role: 'customer',
        googleId: googleData.id,
        picture: googleData.picture,
        createdAt: new Date().toISOString(),
      };

      users.push(newUser);
      fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
      
      logger.info({ email: lowerEmail }, 'New Google user created (file)');
      return newUser;
    } catch (err) {
      logger.error('Failed to store Google user:', err.message);
      throw new Error('Failed to authenticate with Google');
    }
  },

  /**
   * Send welcome email to new Google user
   */
  sendGoogleWelcomeEmail: async (email, name, sendEmailFn) => {
    try {
      await sendEmailFn({
        to: email,
        subject: 'Welcome to MegaPark Hotel & Resort - Google Sign-In Successful',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
              <h1 style="margin: 0;">Welcome to MegaPark! 🎉</h1>
            </div>
            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
              <p>Hi ${name},</p>
              <p>Your Google account has been successfully linked to MegaPark Hotel & Resort.</p>
              
              <p style="margin-top: 20px; font-weight: bold;">You can now:</p>
              <ul>
                <li>Browse our premium menu items</li>
                <li>Book rooms and suites</li>
                <li>Request event hall quotes</li>
                <li>Track your orders and bookings</li>
                <li>Manage your account settings</li>
              </ul>

              <p style="margin-top: 20px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>🔒 Security Tip:</strong> Google Sign-In keeps your account secure. Your password is managed by Google.
              </p>

              <div style="margin-top: 30px; text-align: center;">
                <a href="http://localhost:5173" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                  Go to MegaPark
                </a>
              </div>

              <p style="margin-top: 30px; font-size: 12px; color: #666;">
                If you have any questions, please contact us at support@megapark.com
              </p>
            </div>
          </div>
        `
      });
    } catch (err) {
      console.error('Failed to send Google welcome email:', err);
      // Don't throw - allow login even if email fails
    }
  }
};
