# Roam Calendar Auth Backend

Minimal OAuth backend for the Roam Calendar extension. Handles Google token exchange and refresh securely.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/oauth/token` | Exchange auth code for tokens |
| POST | `/oauth/refresh` | Refresh expired access token |
| GET | `/health` | Health check |

## Setup

### 1. Google Cloud Console Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new project (or select existing)
3. Enable Google Calendar API
4. Create OAuth 2.0 credentials:
   - Application type: Web application
   - Authorized JavaScript origins: `https://roamresearch.com`
   - Authorized redirect URIs: `https://your-backend-url.com/oauth/callback` (or use `postmessage` for popup flow)
5. Copy the Client ID and Client Secret

### 2. Local Development

```bash
# Clone the repo
git clone <your-repo-url>
cd roam-calendar-auth-backend

# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Edit .env with your credentials
nano .env

# Run locally
npm run dev
```

### 3. Deploy to Northflank

1. Create a new service in Northflank
2. Connect your GitHub repository
3. Set environment variables in Northflank dashboard:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `ALLOWED_ORIGINS=https://roamresearch.com`
4. Deploy!

### 4. Update Google Cloud Console

After deployment, add your Northflank URL to:
- Authorized JavaScript origins: `https://your-northflank-url.com`
- Authorized redirect URIs: `https://your-northflank-url.com/oauth/callback`

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GOOGLE_CLIENT_ID` | OAuth client ID from Google Console | `xxx.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | OAuth client secret (keep secure!) | `GOCSPX-xxx` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `https://roamresearch.com` |
| `PORT` | Server port (auto-set by host) | `3000` |

## API Usage

### Exchange Authorization Code for Tokens

```bash
POST /oauth/token
Content-Type: application/json

{
  "code": "4/0AanRRrt...",
  "redirect_uri": "postmessage"
}
```

Response:
```json
{
  "access_token": "ya29.a0...",
  "refresh_token": "1//0g...",
  "expires_in": 3599,
  "token_type": "Bearer",
  "scope": "https://www.googleapis.com/auth/calendar"
}
```

### Refresh Access Token

```bash
POST /oauth/refresh
Content-Type: application/json

{
  "refresh_token": "1//0g..."
}
```

Response:
```json
{
  "access_token": "ya29.a0...",
  "expires_in": 3599,
  "token_type": "Bearer",
  "scope": "https://www.googleapis.com/auth/calendar"
}
```

## Security Notes

- Never commit `.env` file to version control
- Keep `GOOGLE_CLIENT_SECRET` secure
- Use HTTPS in production
- Limit `ALLOWED_ORIGINS` to trusted domains only
- Regularly rotate OAuth credentials

## License

MIT
