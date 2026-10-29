const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const escapeHtml = require('escape-html');
const { csrfSync } = require('csrf-sync');

const { SESSION_SECRET } = process.env;
if (!SESSION_SECRET) throw new Error('SESSION_SECRET must be set');

const app = express();
app.set('trust proxy', 1); // only if behind a proxy/load balancer
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 },
}));

const { csrfSynchronisedProtection, generateToken, invalidCsrfTokenError } = csrfSync({
  getTokenFromRequest: (req) => req.body?._csrf,
});

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).send('Unauthorized');
  next();
}

const emailLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.get('/update-email', requireAuth, (req, res) => {
  res.send(`
    <form action="/update-email" method="POST">
      <input type="hidden" name="_csrf" value="${escapeHtml(generateToken(req))}">
      <label for="email">New Email:</label>
      <input type="email" name="email" id="email" required maxlength="254">
      <button type="submit">Update Email</button>
    </form>
  `);
});

app.post('/update-email', emailLimiter, requireAuth, csrfSynchronisedProtection,
  async (req, res, next) => {
    try {
      const newEmail = String(req.body.email ?? '').trim().toLowerCase();
      if (newEmail.length > 254 || !emailRegex.test(newEmail)) {
        return res.status(400).send('Invalid email address');
      }
      const db = require('./db');
      await db.updateUserEmail(req.session.userId, newEmail);
      res.status(200).send('Email updated successfully');
    } catch (err) {
      next(err);
    }
  });

app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError) return res.status(403).send('Invalid CSRF token');
  console.error(err);
  res.status(500).send('Internal server error');
});

app.listen(3000, () => console.log('Server running on port 3000'));