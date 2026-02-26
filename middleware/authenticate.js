const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-key';

// Verify and decode JWT from Authorization header
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: missing or invalid token' });
  }

  const token = authHeader.slice(7); // Remove "Bearer "
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Attach user info to request
    return next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }
};

// Generate short-lived access token (default 15m)
const generateAccessToken = (user, expires = process.env.JWT_EXPIRES || '15m') => {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, type: 'access' },
    JWT_SECRET,
    { expiresIn: expires }
  );
};

// Generate long-lived refresh token (default 7d)
const generateRefreshToken = (user, expires = process.env.JWT_REFRESH_EXPIRES || '7d') => {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, type: 'refresh' },
    JWT_REFRESH_SECRET,
    { expiresIn: expires }
  );
};

// Generate token pair
const generateTokenPair = (user) => ({
  accessToken: generateAccessToken(user),
  refreshToken: generateRefreshToken(user)
});

// Refresh access token using refresh token
const refreshAccessToken = (refreshToken) => {
  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    if (decoded.type !== 'refresh') throw new Error('Invalid token type');
    const user = { id: decoded.id, email: decoded.email, role: decoded.role };
    return generateTokenPair(user);
  } catch (e) {
    throw new Error(`Invalid refresh token: ${e.message}`);
  }
};

// Legacy single token generator (kept for backward compatibility)
const generateToken = (user) => jwt.sign(
  { id: user.id, email: user.email, role: user.role },
  JWT_SECRET,
  { expiresIn: process.env.JWT_EXPIRES || '24h' }
);

module.exports = {
  authenticate,
  generateToken,
  generateAccessToken,
  generateRefreshToken,
  generateTokenPair,
  refreshAccessToken
};
