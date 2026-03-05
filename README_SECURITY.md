# Secure Portfolio Backend - Security Documentation

This backend is designed with a "Security-First" approach, implementing multiple layers of protection to safeguard your portfolio and server.

## 🛡️ Security Layers

### 1. Secure HTTP Headers (Helmet)
Uses `helmet` to set various HTTP headers that protect against common attacks like Clickjacking, Sniffing, and XSS. It also implements a strict **Content Security Policy (CSP)**.

### 2. Rate Limiting
Prevents Brute-Force and DoS attacks by limiting the number of requests an IP can make.
- **General API**: 100 requests / 15 mins.
- **Auth Routes**: 5 failed attempts / hour.

### 3. Input Validation & Sanitization
- **express-validator**: Validates and escapes all user input (Contact form, Login).
- **xss-clean**: Automatically sanitizes user input from POST body, GET queries, and URL parameters to prevent XSS.
- **hpp**: Protects against HTTP Parameter Pollution.

### 4. Suspicious Request Monitoring
A custom middleware (`securityMonitor`) scans every request for common exploit patterns:
- SQL Injection (`UNION SELECT`, `OR '1'='1'`)
- XSS tags (`<script>`, `onload=`)
- Path Traversal (`../`, `/etc/passwd`)
- Sensitive path access (`/.env`, `/wp-admin`)

### 5. Authentication & Authorization
- **JWT (JSON Web Tokens)**: Secure, stateless authentication.
- **Bcrypt**: Industry-standard password hashing with 12 salt rounds.
- **Role-Based Access Control (RBAC)**: Restricts sensitive endpoints (like `/api/stats`) to admin users only.

### 6. Real-time Alerting (Telegram)
The server sends immediate Telegram notifications for:
- Suspicious activity detection.
- Failed login attempts.
- Blocked sensitive path access.

### 7. Logging & Monitoring
- **Winston**: Structured logging to files (`logs/combined.log`, `logs/error.log`).
- **SQLite Audit Log**: Security events are stored in the `security_logs` table for later review.

## 🚀 How to Run

1. **Install Dependencies**: `npm install`
2. **Configure Environment**: Copy `.env.example` to `.env` and fill in the values.
3. **Setup Admin**: 
   - Set `ADMIN_SETUP_KEY` in `.env`.
   - Send a POST request to `/api/auth/setup-admin` with `username`, `password`, and `secretKey`.
4. **Start Server**: `npm run dev`

## 📁 Project Structure
```
/
├── server.ts              # Main entry point & Middleware config
├── src/
│   └── backend/
│       ├── db/            # SQLite database initialization
│       ├── middleware/    # Security & Auth logic
│       ├── routes/        # Auth & API endpoints
│       └── services/      # Logger & Telegram alerting
├── logs/                  # Application logs
└── database.sqlite        # Persistent data storage
```
