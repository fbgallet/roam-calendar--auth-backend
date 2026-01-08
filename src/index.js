/**
 * OAuth Backend for Roam Calendar Extension
 *
 * Endpoints:
 *   POST /oauth/token   - Exchange authorization code for tokens
 *   POST /oauth/refresh - Refresh an expired access token
 *   GET  /health        - Health check
 */

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Environment variables (set these in Northflank)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || ['https://roamresearch.com'];

// Middleware
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/**
 * Exchange authorization code for tokens
 * Called once after user authorizes in the OAuth popup
 */
app.post('/oauth/token', async (req, res) => {
  const { code, redirect_uri } = req.body;
  const requestId = Date.now().toString(36); // Simple request ID for log correlation

  console.log(`[${requestId}] Token exchange request received`);
  console.log(`[${requestId}] redirect_uri: ${redirect_uri || 'postmessage (default)'}`);
  console.log(`[${requestId}] code length: ${code ? code.length : 0} chars`);

  if (!code) {
    console.log(`[${requestId}] ERROR: Missing authorization code`);
    return res.status(400).json({ error: 'Missing authorization code' });
  }

  try {
    console.log(`[${requestId}] Exchanging code with Google...`);
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirect_uri || 'postmessage', // 'postmessage' for popup flow
      }),
    });

    const data = await response.json();

    if (data.error) {
      console.error(`[${requestId}] Token exchange error from Google: ${data.error}`);
      console.error(`[${requestId}] Error description: ${data.error_description || 'none'}`);
      return res.status(400).json({ error: data.error, description: data.error_description });
    }

    // Return tokens to client
    // IMPORTANT: The client should securely store the refresh_token
    console.log(`[${requestId}] SUCCESS: Token exchange complete`);
    console.log(`[${requestId}] Received refresh_token: ${data.refresh_token ? 'yes' : 'no'}`);
    console.log(`[${requestId}] Token expires_in: ${data.expires_in}s`);

    res.json({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
      token_type: data.token_type,
      scope: data.scope,
    });
  } catch (error) {
    console.error(`[${requestId}] Token exchange failed:`, error.message);
    res.status(500).json({ error: 'Token exchange failed' });
  }
});

/**
 * Refresh an expired access token
 * Called automatically when access_token expires (~1 hour)
 */
app.post('/oauth/refresh', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: 'Missing refresh token' });
  }

  try {
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token,
        grant_type: 'refresh_token',
      }),
    });

    const data = await response.json();

    if (data.error) {
      console.error('Token refresh error:', data);
      return res.status(400).json({ error: data.error, description: data.error_description });
    }

    // Return new access token
    // Note: Google typically doesn't return a new refresh_token
    res.json({
      access_token: data.access_token,
      expires_in: data.expires_in,
      token_type: data.token_type,
      scope: data.scope,
    });
  } catch (error) {
    console.error('Token refresh failed:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`OAuth backend running on port ${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
});
