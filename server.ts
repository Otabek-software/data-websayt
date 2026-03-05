import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import helmet from 'helmet';
import cors from 'cors';
import hpp from 'hpp';
import xss from 'xss-clean';
import logger from './src/backend/services/logger.js';
import { securityMonitor, pathBlocker, apiLimiter } from './src/backend/middleware/security.js';
import authRoutes from './src/backend/routes/auth.js';
import apiRoutes from './src/backend/routes/api.js';
import fs from 'fs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Ensure logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// 1. SECURITY LAYERS (Middleware)
// --------------------------------

// Set secure HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://picsum.photos"],
      connectSrc: ["'self'", "https://api.telegram.org"],
    },
  },
}));

// Enable CORS with specific options
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Body parsing with size limits (Prevent large payload attacks)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Prevent HTTP Parameter Pollution
app.use(hpp());

// Data Sanitization against XSS
app.use(xss());

// Custom Security Monitoring (Detects SQLi/XSS patterns)
app.use(securityMonitor);

// Block common scanner paths
app.use(pathBlocker);

// Rate Limiting
app.use('/api/', apiLimiter);

// 2. ROUTES
// --------------------------------

// Auth Routes
app.use('/api/auth', authRoutes);

// API Routes
app.use('/api', apiRoutes);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// SPA Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 3. ERROR HANDLING
// --------------------------------

app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
  
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// 4. START SERVER
// --------------------------------

app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Secure server running at http://0.0.0.0:${PORT}`);
});
