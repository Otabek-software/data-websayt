import express, { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import db from '../db/index.js';
import logger from '../services/logger.js';
import { sendTelegramAlert } from '../services/telegram.js';
import { authenticateToken, authorizeRole } from '../middleware/auth.js';

const router = express.Router();

// Visitor tracking
router.post('/track', async (req: Request, res: Response) => {
  try {
    const result = db.prepare('UPDATE visit_counts SET count = count + 1 WHERE id = 1').run();
    const row = db.prepare('SELECT count FROM visit_counts WHERE id = 1').get() as any;
    const newCount = row.count;

    const message = `👋 *New visitor*\nTotal visits: ${newCount}`;
    await sendTelegramAlert(message, 'INFO');

    res.json({ success: true, count: newCount });
  } catch (error) {
    logger.error('Tracking error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Contact form
router.post('/contact', [
  body('name').trim().notEmpty().escape(),
  body('email').isEmail().normalizeEmail(),
  body('message').trim().notEmpty().escape(),
], async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, message: userMessage } = req.body;
  const timestamp = new Date().toLocaleString();

  const telegramMsg = `📩 *New Contact Form Submission*\n\n` +
    `👤 *Name:* ${name}\n` +
    `📧 *Email:* ${email}\n` +
    `💬 *Message:* ${userMessage}\n` +
    `⏰ *Time:* ${timestamp}`;

  try {
    await sendTelegramAlert(telegramMsg, 'INFO');
    res.json({ success: true, message: 'Message sent successfully!' });
  } catch (error) {
    logger.error('Contact form error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Protected stats route
router.get('/stats', authenticateToken, authorizeRole('admin'), (req: Request, res: Response) => {
  const row = db.prepare('SELECT count FROM visit_counts WHERE id = 1').get() as any;
  res.json({ count: row.count });
});

// Protected security logs route
router.get('/security-logs', authenticateToken, authorizeRole('admin'), (req: Request, res: Response) => {
  const logs = db.prepare('SELECT * FROM security_logs ORDER BY created_at DESC LIMIT 100').all();
  res.json(logs);
});

export default router;
