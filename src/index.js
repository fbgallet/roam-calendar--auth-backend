/**
 * OAuth Backend for Roam Calendar Extension
 *
 * Endpoints:
 *   GET  /oauth/callback - OAuth redirect callback (for redirect flow)
 *   POST /oauth/token    - Exchange authorization code for tokens
 *   POST /oauth/refresh  - Refresh an expired access token
 *   GET  /health         - Health check
 */

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Environment variables (set these in Northflank)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || ['https://roamresearch.com'];

// In-memory storage for pending OAuth sessions (for Desktop polling)
// Format: { sessionId: { code, state, error, timestamp } }
const pendingAuthSessions = new Map();

// Clean up old sessions every 5 minutes (sessions expire after 10 minutes)
setInterval(() => {
  const now = Date.now();
  const expireTime = 10 * 60 * 1000; // 10 minutes
  for (const [sessionId, data] of pendingAuthSessions) {
    if (now - data.timestamp > expireTime) {
      pendingAuthSessions.delete(sessionId);
    }
  }
}, 5 * 60 * 1000);

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
 * OAuth callback endpoint (redirect flow)
 * Google redirects here after user grants permission
 * This page posts the auth code back to the opener window and closes
 *
 * For Desktop apps (no opener), the state may contain a session ID for polling:
 * Format: csrfState|sessionId
 */
app.get('/oauth/callback', (req, res) => {
  const { code, state, error } = req.query;
  const requestId = Date.now().toString(36);

  console.log(`[${requestId}] OAuth callback received`);
  console.log(`[${requestId}] Has code: ${!!code}, Has state: ${!!state}, Has error: ${!!error}`);
  if (error) {
    console.log(`[${requestId}] OAuth error: ${error}`);
  }

  // Check if state contains a session ID (format: csrfState|sessionId)
  let sessionId = null;
  let csrfState = state;
  if (state && state.includes('|')) {
    const parts = state.split('|');
    csrfState = parts[0];
    sessionId = parts[1];
    console.log(`[${requestId}] Desktop session detected: ${sessionId}`);
  }

  // If we have a session ID, store the auth data for polling
  if (sessionId) {
    pendingAuthSessions.set(sessionId, {
      code: code || null,
      state: csrfState, // Store original CSRF state without session ID
      error: error || null,
      timestamp: Date.now()
    });
    console.log(`[${requestId}] Stored auth data for session: ${sessionId}`);
  }

  // Send HTML that posts message back to opener and closes
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Authentication Complete</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
    .container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    h1 { color: #333; margin-bottom: 10px; }
    p { color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${error ? 'Authentication Failed' : 'Authentication Complete'}</h1>
    <p>${error ? 'Please close this window and try again.' : 'You can close this window and return to Roam.'}</p>
  </div>
  <script>
    // Try postMessage for browser popup flow
    if (window.opener) {
      window.opener.postMessage({
        type: 'oauth-callback',
        code: ${JSON.stringify(code || null)},
        state: ${JSON.stringify(csrfState || null)},
        error: ${JSON.stringify(error || null)}
      }, '*');
      setTimeout(() => window.close(), 1500);
    }
    // For Desktop (no opener), the page just shows the message
    // and the app polls /oauth/poll to get the auth data
  </script>
</body>
</html>
  `);
});

/**
 * Poll for OAuth completion (Desktop app flow)
 * Desktop apps can't receive postMessage, so they poll this endpoint
 */
app.get('/oauth/poll', (req, res) => {
  const { session } = req.query;

  if (!session) {
    return res.status(400).json({ error: 'Missing session parameter' });
  }

  const authData = pendingAuthSessions.get(session);

  if (!authData) {
    // Session not found or not yet completed
    return res.json({ status: 'pending' });
  }

  // Found! Return the auth data and clean up
  pendingAuthSessions.delete(session);

  res.json({
    status: 'completed',
    code: authData.code,
    state: authData.state,
    error: authData.error
  });
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
