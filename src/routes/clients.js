const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { requireClient } = require('../middleware/auth');
const { serializeOrder } = require('../utils/serializeOrder');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function publicClient(row) {
  if (!row) return null;
  const { id, email, societe, contact, tel, adresse, created_at } = row;
  return { id, email, societe, contact, tel, adresse, createdAt: created_at };
}

// POST /api/clients/register
router.post('/register', (req, res) => {
  const { societe, contact, tel, adresse, email, code } = req.body || {};

  if (!societe || !contact || !tel || !adresse || !email) {
    return res.status(400).json({ error: 'Merci de remplir tous les champs.' });
  }
  if (!EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Adresse email invalide.' });
  }
  if (!/^\d{4,8}$/.test(code || '')) {
    return res.status(400).json({ error: "Le code d'accès doit contenir entre 4 et 8 chiffres." });
  }

  const existing = db.prepare('SELECT id FROM clients WHERE email = ?').get(email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  }

  const codeHash = bcrypt.hashSync(code, 10);
  const info = db.prepare(`
    INSERT INTO clients (email, societe, contact, tel, adresse, code_hash)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(email.toLowerCase(), societe, contact, tel, adresse, codeHash);

  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(info.lastInsertRowid);
  req.session.clientId = client.id;
  res.status(201).json({ client: publicClient(client) });
});

// POST /api/clients/login
router.post('/login', (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) {
    return res.status(400).json({ error: 'Merci de renseigner votre email et votre code.' });
  }
  const client = db.prepare('SELECT * FROM clients WHERE email = ?').get(email.toLowerCase());
  if (!client || !bcrypt.compareSync(code, client.code_hash)) {
    return res.status(401).json({ error: "Email ou code d'accès incorrect." });
  }
  req.session.clientId = client.id;
  res.json({ client: publicClient(client) });
});

// POST /api/clients/logout
router.post('/logout', (req, res) => {
  delete req.session.clientId;
  res.json({ ok: true });
});

// GET /api/clients/me
router.get('/me', (req, res) => {
  if (!req.session.clientId) return res.json({ client: null });
  const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(req.session.clientId);
  if (!client) {
    delete req.session.clientId;
    return res.json({ client: null });
  }
  res.json({ client: publicClient(client) });
});

// GET /api/clients/orders — historique du client connecté
router.get('/orders', requireClient, (req, res) => {
  const orders = db.prepare(`
    SELECT * FROM orders WHERE client_id = ? ORDER BY created_at DESC
  `).all(req.session.clientId);

  const itemsStmt = db.prepare('SELECT service_id as id, name, code, price, qty, delivered_qty as deliveredQty FROM order_items WHERE order_id = ?');
  const serialized = orders.map(o => serializeOrder(o, itemsStmt.all(o.id)));
  res.json({ orders: serialized });
});

// ---------- questionnaire de satisfaction (NPS) ----------

// GET /api/clients/nps/status — indique si le client connecté a déjà
// répondu ce mois-ci civil, pour savoir s'il faut lui proposer le
// questionnaire (au plus une fois par mois, pas à chaque connexion).
router.get('/nps/status', requireClient, (req, res) => {
  const row = db.prepare(`
    SELECT 1 FROM nps_responses
    WHERE client_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    LIMIT 1
  `).get(req.session.clientId);
  res.json({ alreadyResponded: !!row });
});

// POST /api/clients/nps — enregistre la réponse du mois. N'empêche pas
// une deuxième soumission côté serveur (l'interface ne la propose plus
// une fois répondu, mais mieux vaut ne pas bloquer si jamais) — le calcul
// admin utilisera de toute façon la plus récente par mois et par client.
router.post('/nps', requireClient, (req, res) => {
  const { score, comment } = req.body || {};
  const scoreNum = parseInt(score, 10);
  if (!Number.isInteger(scoreNum) || scoreNum < 0 || scoreNum > 10) {
    return res.status(400).json({ error: 'Note invalide (0 à 10 attendu).' });
  }
  db.prepare('INSERT INTO nps_responses (client_id, score, comment) VALUES (?, ?, ?)')
    .run(req.session.clientId, scoreNum, (comment || '').trim() || null);
  res.status(201).json({ ok: true });
});

module.exports = router;
