import dotenv from 'dotenv';
import logger from './logger.js';

dotenv.config();

const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const CHAT_ID = process.env.CHAT_ID;

export async function sendTelegramAlert(message: string, severity: 'INFO' | 'WARNING' | 'CRITICAL' = 'INFO') {
  if (!TELEGRAM_TOKEN || !CHAT_ID) {
    logger.warn('Telegram credentials missing. Skipping alert.');
    return;
  }

  const emoji = severity === 'CRITICAL' ? '🚨' : severity === 'WARNING' ? '⚠️' : 'ℹ️';
  const formattedMessage = `${emoji} *[${severity}] Security Alert*\n\n${message}\n\n⏰ *Time:* ${new Date().toLocaleString()}`;

  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: CHAT_ID,
        text: formattedMessage,
        parse_mode: 'Markdown',
      }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      logger.error('Telegram API error:', errorData);
    }
  } catch (error) {
    logger.error('Error sending Telegram alert:', error);
  }
}
