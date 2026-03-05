import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import logger from '../services/logger.js';
import { sendTelegramAlert } from '../services/telegram.js';
import db from '../db/index.js';

// Rate limiter for general API
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limiter for auth routes
export const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 failed attempts per hour
  message: 'Too many login attempts, please try again after an hour',
  skipSuccessfulRequests: true,
});

// Suspicious pattern detection
const SUSPICIOUS_PATTERNS = [
  /<script/i,
  /javascript:/i,
  /onload=/i,
  /onerror=/i,
  /UNION SELECT/i,
  /OR '1'='1'/i,
  /--/i,
  /DROP TABLE/i,
  /INSERT INTO/i,
  /\.\.\//, // Path traversal
  /etc\/passwd/i,
];

export function securityMonitor(req: Request, res: Response, next: NextFunction) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const url = req.originalUrl;
  const body = JSON.stringify(req.body);
  const query = JSON.stringify(req.query);

  const checkString = `${url} ${body} ${query}`;

  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(checkString)) {
      const message = `Suspicious activity detected from IP: ${ip}\nPattern: ${pattern}\nURL: ${url}\nUA: ${userAgent}`;
      
      logger.warn(message);
      
      // Log to DB
      db.prepare('INSERT INTO security_logs (type, message, ip, user_agent, severity) VALUES (?, ?, ?, ?, ?)')
        .run('SUSPICIOUS_REQUEST', message, String(ip), userAgent, 'WARNING');

      // Alert via Telegram
      sendTelegramAlert(message, 'WARNING');

      return res.status(403).json({ error: 'Forbidden: Suspicious activity detected' });
    }
  }

  next();
}

// Block common scanner paths
const BLOCKED_PATHS = [
  '/wp-admin',
  '/wp-login.php',
  '/.env',
  '/.git',
  '/phpmyadmin',
  '/xmlrpc.php',
];

export function pathBlocker(req: Request, res: Response, next: NextFunction) {
  if (BLOCKED_PATHS.some(path => req.originalUrl.includes(path))) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const message = `Blocked access attempt to sensitive path: ${req.originalUrl} from IP: ${ip}`;
    
    logger.warn(message);
    sendTelegramAlert(message, 'CRITICAL');
    
    return res.status(404).send('Not Found');
  }
  next();
}
