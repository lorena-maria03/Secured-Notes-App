# Secured Notes App

A FastAPI + vanilla JS notes app with end-to-end encryption, two-factor authentication (email OTP + TOTP authenticator app), and password reset.

## Features

- **End-to-end encrypted notes** — AES-256-CBC per note, keys wrapped with RSA-2048 OAEP
- **Digital signatures** — RSA-PSS sign/verify on every note; tamper detection shown in the UI
- **Two-factor authentication** — email OTP (default) or TOTP authenticator app (Authy, Google Authenticator, etc.)
- **Password reset** — sends a reset link via email; tokens expire after 15 minutes
- **Steganography** — hide/extract note content inside PNG images using LSB encoding
- **SQL injection checker** — pattern-based checker for demo/educational use
- **Rate limiting** — 5 failed login attempts per 15-minute window triggers a 30-minute hard lockout; also applied to password reset and email OTP requests

## Setup

1. Copy the example env file and fill in your values:
   ```bash
   cp .env.example .env
   ```

   | Variable | Description |
   |----------|-------------|
   | `SECRET_KEY` | JWT signing secret (any long random string) |
   | `PASSWORD_PEPPER` | Appended to passwords before bcrypt hashing |
   | `SMTP_HOST` | SMTP server host (default: `localhost`) |
   | `SMTP_PORT` | SMTP port — `1025` for Mailpit, `587` for TLS, `465` for SSL |
   | `SMTP_USER` | SMTP username (leave blank for Mailpit) |
   | `SMTP_PASSWORD` | SMTP password (leave blank for Mailpit) |
   | `SMTP_FROM_EMAIL` | From address used in outgoing emails |

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the App

The easiest way is to use the `start.sh` script — it starts Mailpit (local email catcher) and the backend together:

```bash
./start.sh
```

Or start the backend manually from the `backend/` directory:

```bash
cd backend
uvicorn main:app --reload
```

Then open the app at: **http://localhost:8000**

## Email (Mailpit)

Mailpit catches all outgoing emails locally so you can inspect OTP codes and password reset links without a real mail server.

Install Mailpit (macOS):
```bash
brew install mailpit
```

The `.env.example` is pre-configured to point at Mailpit (`SMTP_HOST=localhost`, `SMTP_PORT=1025`). Any email the app sends — login OTP codes, password reset links — will appear in the Mailpit inbox instead of being delivered to a real address.

Mailpit web inbox: **http://localhost:8025**

## start.sh reference

```
  ┌────────────────────────────────┬────────────────────────────┐
  │            Command             │        What it does        │
  ├────────────────────────────────┼────────────────────────────┤
  │ ./start.sh or ./start.sh start │ Start mailpit + backend    │
  ├────────────────────────────────┼────────────────────────────┤
  │ ./start.sh stop                │ Stop both                  │
  ├────────────────────────────────┼────────────────────────────┤
  │ ./start.sh restart             │ Stop then start both       │
  ├────────────────────────────────┼────────────────────────────┤
  │ ./start.sh status              │ Show running/stopped state │
  ├────────────────────────────────┼────────────────────────────┤
  │ ./start.sh logs backend        │ Tail backend logs          │
  ├────────────────────────────────┼────────────────────────────┤
  │ ./start.sh logs mailpit        │ Tail mailpit logs          │
  └────────────────────────────────┴────────────────────────────┘
```

