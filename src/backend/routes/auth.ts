import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import db from '../db/index.js';
import logger from '../services/logger.js';
import { sendTelegramAlert } from '../services/telegram.js';
import { authLimiter } from '../middleware/security.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-key';

// Login route
router.post('/login', authLimiter, [
  body('username').trim().notEmpty().escape(),
  body('password').notEmpty(),
], async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as any;

    if (!user || !(await bcrypt.compare(password, user.password))) {
      const message = `Failed login attempt for user: ${username} from IP: ${ip}`;
      logger.warn(message);
      
      // Log to DB
      db.prepare('INSERT INTO security_logs (type, message, ip, severity) VALUES (?, ?, ?, ?)')
        .run('FAILED_LOGIN', message, String(ip), 'WARNING');

      // Alert via Telegram
      sendTelegramAlert(message, 'WARNING');

      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    logger.info(`Successful login for user: ${username} from IP: ${ip}`);
    
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create initial admin user (for demo purposes, should be disabled in production)
router.post('/setup-admin', async (req: Request, res: Response) => {
  const { username, password, secretKey } = req.body;
  
  if (secretKey !== process.env.ADMIN_SETUP_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)')
      .run(username, hashedPassword, 'admin');
    
    res.json({ success: true, message: 'Admin user created' });
  } catch (error) {
    res.status(400).json({ error: 'User already exists or error occurred' });
  }
});

export default router;
