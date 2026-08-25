const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { requireAdmin } = require('../middleware/auth');
const { buildDeliveryNoteText, buildDeliveryNoteHtml } = require('../utils/deliveryNote');
const { buildDeliveryNotePdf } = require('../utils/pdf');
const { sendMail, isConfigured } = require('../utils/mailer');
const { serializeOrder } = require('../utils/serializeOrder');
const { getServicesById } = require('../services');
const { sendWhatsAppNotification } = require('../utils/whatsapp');
const { notifyOrderDelivered } = require('../utils/webhookNotify');

const router = express.Router();

const STATUSES = ['recue', 'traitement', 'prete', 'livree'];

const itemsStmt = db.prepare('SELECT service_id as id, name, code, sage_code as sageCode, price, qty, delivered_qty as deliveredQty FROM order_items WHERE order_id = ?');
function getItems(orderId) { return itemsStmt.all(orderId); }

function getAdminRow() {
  return db.prepare('SELECT * FROM admin WHERE id = 1').get();
}

// GET /api/admin/status — l'admin existe-t-il déjà ? la session en cours est-elle déverrouillée ?
router.get('/status', (req, res) => {
  const admin = getAdminRow();
  res.json({ exists: Boolean(admin), unlocked: Boolean(req.session.isAdmin) });
});

// POST /api/admin/setup — définit le mot de passe la toute première fois
router.post('/setup', (req, res) => {
  if (getAdminRow()) {
    return res.status(409).json({ error: 'Un mot de passe administrateur existe déjà.' });
  }
  const { password } = req.body || {};
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères.' });
  }
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO admin (id, password_hash, delivery_email) VALUES (1, ?, NULL)').run(hash);
  req.session.isAdmin = true;
  res.status(201).json({ ok: true });
});

// POST /api/admin/login
router.post('/login', (req, res) => {
  const admin = getAdminRow();
  if (!admin) return res.status(409).json({ error: "Aucun mot de passe défini. Passez d'abord par la configuration." });
  const { password } = req.body || {};
  if (!password || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).json({ error: 'Mot de passe incorrect.' });
  }
  req.session.isAdmin = true;
  res.json({ ok: true });
});

// POST /api/admin/logout
router.post('/logout', (req, res) => {
  delete req.session.isAdmin;
  res.json({ ok: true });
});

// Tout ce qui suit nécessite une session admin déverrouillée
router.use(requireAdmin);

// GET /api/admin/clients — liste des comptes clients (hôtels), pour les
// sélecteurs d'hôtel (commandes automatiques, etc.) et l'écran de gestion.
router.get('/clients', (req, res) => {
  const rows = db.prepare('SELECT id, email, societe, contact, tel, adresse, created_at as createdAt FROM clients ORDER BY societe').all();
  res.json({ clients: rows });
});

// POST /api/admin/clients — créer un compte hôtel manuellement (sans
// passer par l'auto-inscription publique) — utile pour préparer un accès
// avant même que l'hôtel s'en serve, en lui communiquant le code choisi.
router.post('/clients', (req, res) => {
  const { societe, contact, tel, adresse, email, code } = req.body || {};
  if (!societe || !contact || !tel || !adresse || !email) {
    return res.status(400).json({ error: 'Merci de remplir tous les champs.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Adresse email invalide.' });
  }
  if (!/^\d{4,8}$/.test(code || '')) {
    return res.status(400).json({ error: "Le code d'accès doit contenir entre 4 et 8 chiffres." });
  }
  const existing = db.prepare('SELECT id FROM clients WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });

  const codeHash = bcrypt.hashSync(code, 10);
  const info = db.prepare(`
    INSERT INTO clients (email, societe, contact, tel, adresse, code_hash)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(email.toLowerCase(), societe.trim(), contact.trim(), tel.trim(), adresse.trim(), codeHash);

  const row = db.prepare('SELECT id, email, societe, contact, tel, adresse, created_at as createdAt FROM clients WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json({ client: row });
});

// PUT /api/admin/clients/:id — modifier les coordonnées d'un hôtel, et
// éventuellement réinitialiser son code d'accès (champ "code" optionnel :
// absent = inchangé). Nécessaire puisque le code n'est jamais récupérable
// depuis l'inscription — c'est le seul moyen de dépanner un hôtel qui l'a
// oublié.
router.put('/clients/:id', (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM clients WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Hôtel introuvable.' });

  const { societe, contact, tel, adresse, email, code } = req.body || {};
  if (email !== undefined && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Adresse email invalide.' });
  }
  if (email !== undefined && email.toLowerCase() !== existing.email) {
    const emailTaken = db.prepare('SELECT id FROM clients WHERE email = ? AND id != ?').get(email.toLowerCase(), id);
    if (emailTaken) return res.status(409).json({ error: 'Cet email est déjà utilisé par un autre compte.' });
  }
  let codeHash = existing.code_hash;
  if (code) {
    if (!/^\d{4,8}$/.test(code)) return res.status(400).json({ error: "Le code d'accès doit contenir entre 4 et 8 chiffres." });
    codeHash = bcrypt.hashSync(code, 10);
  }

  db.prepare(`
    UPDATE clients SET societe = ?, contact = ?, tel = ?, adresse = ?, email = ?, code_hash = ? WHERE id = ?
  `).run(
    (societe ?? existing.societe).trim(),
    (contact ?? existing.contact).trim(),
    (tel ?? existing.tel).trim(),
    (adresse ?? existing.adresse).trim(),
    (email ?? existing.email).toLowerCase(),
    codeHash,
    id
  );

  const row = db.prepare('SELECT id, email, societe, contact, tel, adresse, created_at as createdAt FROM clients WHERE id = ?').get(id);
  res.json({ client: row });
});

// DELETE /api/admin/clients/:id — les commandes déjà passées ne sont pas
// supprimées (client_id repasse à NULL, elles gardent leur société/contact
// figés au moment de la commande, voir schema.sql).
router.delete('/clients/:id', (req, res) => {
  db.prepare('DELETE FROM clients WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// ---------- jetons API (intégrations B2B) ----------

// GET /api/admin/clients/:id/api-tokens — liste des jetons d'un hôtel.
router.get('/clients/:id/api-tokens', (req, res) => {
  const rows = db.prepare('SELECT id, token, label, created_at as createdAt, last_used_at as lastUsedAt FROM api_tokens WHERE client_id = ? ORDER BY created_at DESC')
    .all(Number(req.params.id));
  res.json({ tokens: rows });
});

// POST /api/admin/clients/:id/api-tokens — génère un nouveau jeton pour
// cet hôtel (ex. pour une intégration avec son propre logiciel de
// commande). Le jeton n'est affiché en clair qu'à cet instant — il reste
// ensuite consultable mais pensé pour être copié tout de suite.
router.post('/clients/:id/api-tokens', (req, res) => {
  const clientId = Number(req.params.id);
  const client = db.prepare('SELECT id FROM clients WHERE id = ?').get(clientId);
  if (!client) return res.status(404).json({ error: 'Hôtel introuvable.' });

  const { label } = req.body || {};
  const token = crypto.randomBytes(24).toString('hex');
  const info = db.prepare('INSERT INTO api_tokens (client_id, token, label) VALUES (?, ?, ?)')
    .run(clientId, token, (label || '').trim() || null);
  const row = db.prepare('SELECT id, token, label, created_at as createdAt, last_used_at as lastUsedAt FROM api_tokens WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json({ token: row });
});

// DELETE /api/admin/api-tokens/:id — révoque un jeton (immédiat).
router.delete('/api-tokens/:id', (req, res) => {
  db.prepare('DELETE FROM api_tokens WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// GET /api/admin/clients/:id/webhook — configuration webhook actuelle.
router.get('/clients/:id/webhook', (req, res) => {
  const row = db.prepare('SELECT webhook_url as webhookUrl, webhook_secret as webhookSecret FROM clients WHERE id = ?').get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Hôtel introuvable.' });
  res.json(row);
});

// PUT /api/admin/clients/:id/webhook — définit ou modifie l'URL à
// notifier quand une commande de cet hôtel passe à "livrée". Un secret
// est généré automatiquement à la première configuration (jamais
// régénéré ensuite, sauf demande explicite via le paramètre regenerate).
router.put('/clients/:id/webhook', (req, res) => {
  const clientId = Number(req.params.id);
  const existing = db.prepare('SELECT webhook_secret FROM clients WHERE id = ?').get(clientId);
  if (!existing) return res.status(404).json({ error: 'Hôtel introuvable.' });

  const { webhookUrl, regenerateSecret } = req.body || {};
  if (webhookUrl) {
    try { new URL(webhookUrl); } catch { return res.status(400).json({ error: 'URL invalide.' }); }
  }
  const secret = (regenerateSecret || !existing.webhook_secret) ? crypto.randomBytes(20).toString('hex') : existing.webhook_secret;
  db.prepare('UPDATE clients SET webhook_url = ?, webhook_secret = ? WHERE id = ?').run(webhookUrl || null, secret, clientId);
  res.json({ webhookUrl: webhookUrl || null, webhookSecret: secret });
});

// GET /api/admin/orders/:id/extra — hôtels supplémentaires + commentaires
// d'une commande, chargés à la demande (pas à chaque liste de commandes).
router.get('/orders/:id/extra', (req, res) => {
  const orderId = Number(req.params.id);
  const extraClients = db.prepare(`
    SELECT c.id, c.societe FROM order_extra_clients oec
    JOIN clients c ON c.id = oec.client_id
    WHERE oec.order_id = ? ORDER BY c.societe
  `).all(orderId);
  const comments = db.prepare(`
    SELECT id, author, text, created_at as createdAt FROM order_comments
    WHERE order_id = ? ORDER BY created_at ASC
  `).all(orderId);
  res.json({ extraClients, comments });
});

// PUT /api/admin/orders/:id/extra-clients — définit la liste complète des
// hôtels supplémentaires associés (remplace, ne cumule pas).
router.put('/orders/:id/extra-clients', (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT id FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });

  const { clientIds } = req.body || {};
  if (!Array.isArray(clientIds)) return res.status(400).json({ error: 'clientIds doit être une liste.' });

  const setExtra = db.transaction(() => {
    db.prepare('DELETE FROM order_extra_clients WHERE order_id = ?').run(orderId);
    const insert = db.prepare('INSERT OR IGNORE INTO order_extra_clients (order_id, client_id) VALUES (?, ?)');
    for (const cid of clientIds) insert.run(orderId, Number(cid));
  });
  setExtra();
  res.json({ ok: true });
});

// POST /api/admin/orders/:id/comments — ajoute un message au fil de
// discussion de la commande (l'équipe de production peut se laisser des
// notes, chacune horodatée).
router.post('/orders/:id/comments', (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT id FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });

  const { author, text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Le message ne peut pas être vide.' });

  const info = db.prepare('INSERT INTO order_comments (order_id, author, text) VALUES (?, ?, ?)')
    .run(orderId, (author || '').trim() || null, text.trim());
  const comment = db.prepare('SELECT id, author, text, created_at as createdAt FROM order_comments WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json({ comment });
});

function nextTicket(now) {
  const row = db.prepare('SELECT value FROM order_seq WHERE id = 1').get();
  const seq = row.value + 1;
  db.prepare('UPDATE order_seq SET value = ? WHERE id = 1').run(seq);
  const yy = String(now.getFullYear()).slice(2);
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  return `CZ-${yy}${mm}${dd}-${String(seq).padStart(4, '0')}`;
}

const PRODUCTION_STAGES = ['tri', 'lavage', 'sechage', 'repassage', 'pliage', 'en_stock'];

// POST /api/admin/orders/manual — création manuelle par l'admin, depuis
// l'onglet "Préparation de commande" (statut "recue" par défaut) ou
// "Production" (statut "traitement" avec une étape de départ).
// body: { clientId?, societe?, contact?, tel?, adresse?, items:[{id,qty}],
//         livraisonPrevue?, notes?, status?, productionStage? }
router.post('/orders/manual', (req, res) => {
  const { clientId, items, livraisonPrevue, notes, status, productionStage } = req.body || {};
  let { societe, contact, tel, adresse } = req.body || {};

  if (clientId) {
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(clientId));
    if (!client) return res.status(404).json({ error: 'Hôtel introuvable.' });
    ({ societe, contact, tel, adresse } = client);
  }
  if (!societe || !societe.trim()) {
    return res.status(400).json({ error: 'Merci de renseigner au moins la société (ou de choisir un hôtel enregistré).' });
  }
  contact = contact || '';
  tel = tel || '';
  adresse = adresse || '';
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Merci de sélectionner au moins un article.' });
  }

  const servicesById = getServicesById();
  const resolved = [];
  for (const it of items) {
    const itemId = it.serviceId || it.id; // collectQtyGrid renvoie "serviceId" ; on accepte aussi "id" par tolérance
    const svc = servicesById[itemId];
    const qty = parseInt(it.qty, 10);
    if (!svc) return res.status(400).json({ error: `Article inconnu : ${itemId}` });
    if (!Number.isInteger(qty) || qty <= 0) {
      return res.status(400).json({ error: `Quantité invalide pour ${svc.name}.` });
    }
    resolved.push({ ...svc, qty });
  }

  const finalStatus = STATUSES.includes(status) ? status : 'recue';
  const itemStage = finalStatus === 'traitement' && PRODUCTION_STAGES.includes(productionStage) ? productionStage : 'tri';
  // orders.production_stage n'accepte volontairement PAS "en_stock" (sa
  // contrainte n'a pas été migrée, cette colonne n'étant plus utilisée
  // que comme valeur de départ) — on la plafonne à "pliage" dans ce cas
  // précis, tandis que order_items reçoit la vraie étape choisie.
  const orderStage = itemStage === 'en_stock' ? 'pliage' : itemStage;

  const now = new Date();
  const insertOrder = db.prepare(`
    INSERT INTO orders (ticket, client_id, societe, contact, tel, adresse, livraison_prevue, notes, status, production_stage, created_at)
    VALUES (@ticket, @clientId, @societe, @contact, @tel, @adresse, @livraisonPrevue, @notes, @status, @productionStage, @createdAt)
  `);
  const insertItem = db.prepare(`
    INSERT INTO order_items (order_id, service_id, name, code, sage_code, price, qty, delivered_qty, production_stage)
    VALUES (@orderId, @id, @name, @code, @sageCode, @price, @qty, @qty, @productionStage)
  `);

  const createOrder = db.transaction(() => {
    const ticket = nextTicket(now);
    const info = insertOrder.run({
      ticket,
      clientId: clientId || null,
      societe, contact, tel, adresse,
      livraisonPrevue: livraisonPrevue || null,
      notes: notes || 'Commande créée manuellement par un administrateur.',
      status: finalStatus,
      productionStage: orderStage,
      createdAt: now.toISOString(),
    });
    const orderId = info.lastInsertRowid;
    for (const it of resolved) {
      insertItem.run({ orderId, id: it.id, name: it.name, code: it.code, sageCode: it.sageCode, price: it.price, qty: it.qty, productionStage: itemStage });
    }
    return { orderId, ticket };
  });

  const { orderId, ticket } = createOrder();
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);

  const itemsSummary = resolved.map(i => `${i.name} x${i.qty}`).join(', ');
  sendWhatsAppNotification(`Commande créée manuellement ${ticket} — ${societe} — ${itemsSummary}`)
    .catch(err => console.error('Notification WhatsApp échouée :', err.message));

  res.status(201).json({ order: serializeOrder(order, resolved), ticket });
});

// GET /api/admin/orders — toutes les commandes, tous clients
router.get('/orders', (req, res) => {
  const orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
  res.json({ orders: orders.map(o => serializeOrder(o, getItems(o.id))) });
});

// PATCH /api/admin/orders/:id/status
router.patch('/orders/:id/status', (req, res) => {
  const { status } = req.body || {};
  if (!STATUSES.includes(status)) {
    return res.status(400).json({ error: 'Statut invalide.' });
  }
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });

  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, order.id);

  // Notifie le logiciel du client (si intégré via API et webhook
  // configuré) avec les quantités définitives, sans jamais bloquer la
  // réponse ni faire échouer le changement de statut si l'appel rate.
  if (status === 'livree' && order.client_id) {
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(order.client_id);
    if (client?.webhook_url) {
      notifyOrderDelivered(client, order, getItems(order.id)).catch(() => {});
    }
  }

  res.json({ order: serializeOrder({ ...order, status }, getItems(order.id)) });
});

// PATCH /api/admin/orders/:id/livraison-prevue — définit ou modifie la
// date de livraison prévue d'une commande existante (vide = effacée).
router.patch('/orders/:id/livraison-prevue', (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });

  const { livraisonPrevue } = req.body || {};
  db.prepare('UPDATE orders SET livraison_prevue = ? WHERE id = ?').run(livraisonPrevue || null, orderId);
  res.json({ order: serializeOrder({ ...order, livraison_prevue: livraisonPrevue || null }, getItems(order.id)) });
});

// POST /api/admin/orders/:id/create-followup — crée une commande de
// complément pour le lendemain, reprenant UNIQUEMENT les quantités
// manquantes (qty - delivered_qty) d'une commande livrée partiellement.
// Appelée après confirmation de l'admin, pas automatiquement.
router.post('/orders/:id/create-followup', (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });

  const items = getItems(orderId);
  const missing = items
    .map(it => ({ ...it, missingQty: it.qty - (it.deliveredQty ?? it.qty) }))
    .filter(it => it.missingQty > 0);

  if (missing.length === 0) {
    return res.status(400).json({ error: 'Aucun manquant sur cette commande — rien à reporter.' });
  }

  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  const livraisonPrevue = tomorrow.toISOString().slice(0, 10);

  const now = new Date();
  const insertOrder = db.prepare(`
    INSERT INTO orders (ticket, client_id, societe, contact, tel, adresse, livraison_prevue, notes, status, created_at)
    VALUES (@ticket, @clientId, @societe, @contact, @tel, @adresse, @livraisonPrevue, @notes, 'recue', @createdAt)
  `);
  const insertItem = db.prepare(`
    INSERT INTO order_items (order_id, service_id, name, code, sage_code, price, qty, delivered_qty)
    VALUES (@orderId, @serviceId, @name, @code, @sageCode, @price, @qty, @qty)
  `);

  const createFollowup = db.transaction(() => {
    const ticket = nextTicket(now);
    const info = insertOrder.run({
      ticket,
      clientId: order.client_id,
      societe: order.societe, contact: order.contact, tel: order.tel, adresse: order.adresse,
      livraisonPrevue,
      notes: `Commande de complément suite à livraison partielle de ${order.ticket}.`,
      createdAt: now.toISOString(),
    });
    const followupId = info.lastInsertRowid;
    for (const it of missing) {
      insertItem.run({
        orderId: followupId, serviceId: it.id, name: it.name, code: it.code, sageCode: it.sageCode,
        price: it.price, qty: it.missingQty,
      });
    }
    return { followupId, ticket };
  });

  const { followupId, ticket } = createFollowup();
  const followupOrder = db.prepare('SELECT * FROM orders WHERE id = ?').get(followupId);
  res.status(201).json({ order: serializeOrder(followupOrder, getItems(followupId)) });
});

// PATCH /api/admin/orders/:id/items — ajuste la quantité RÉELLEMENT PRÉPARÉE
// de chaque article (commande "en traitement"). La quantité commandée par le
// client (colonne qty) n'est jamais modifiée : seule delivered_qty change,
// pour que le client puisse toujours voir les deux valeurs sur son aperçu.
router.patch('/orders/:id/items', (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });
  if (order.status !== 'traitement') {
    return res.status(409).json({ error: 'Les quantités ne peuvent être modifiées que pour une commande en traitement.' });
  }

  const { items } = req.body || {};
  if (!Array.isArray(items)) {
    return res.status(400).json({ error: "Liste d'articles invalide." });
  }

  const existing = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(order.id);
  const update = db.prepare('UPDATE order_items SET delivered_qty = ? WHERE order_id = ? AND service_id = ?');

  db.transaction(() => {
    existing.forEach(row => {
      const found = items.find(i => i.id === row.service_id);
      if (!found) return; // article non transmis : on laisse sa valeur actuelle
      const raw = parseInt(found.deliveredQty, 10);
      const deliveredQty = Number.isInteger(raw) && raw >= 0 ? raw : row.delivered_qty;
      update.run(deliveredQty, order.id, row.service_id);
    });
  })();

  res.json({ order: serializeOrder(order, getItems(order.id)) });
});

// POST /api/admin/orders/:id/items — ajoute un article supplémentaire à
// une commande déjà existante (ex. l'hôtel appelle pour en rajouter).
// Le nom/code/prix sont figés au moment de l'ajout, comme pour tout
// article de commande — un changement ultérieur du catalogue ne modifie
// pas rétroactivement cette ligne.
router.post('/orders/:id/items', (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });

  const { serviceId, qty } = req.body || {};
  const servicesById = getServicesById();
  const svc = servicesById[serviceId];
  if (!svc) return res.status(400).json({ error: 'Article inconnu.' });
  const qtyNum = parseInt(qty, 10);
  if (!Number.isInteger(qtyNum) || qtyNum <= 0) {
    return res.status(400).json({ error: 'Quantité invalide.' });
  }

  const existing = db.prepare('SELECT id, qty FROM order_items WHERE order_id = ? AND service_id = ?').get(orderId, serviceId);
  if (existing) {
    // Déjà présent sur cette commande : on augmente la ligne existante
    // plutôt que d'en créer une seconde pour le même article.
    const newQty = existing.qty + qtyNum;
    db.prepare('UPDATE order_items SET qty = ?, delivered_qty = ? WHERE id = ?').run(newQty, newQty, existing.id);
  } else {
    db.prepare(`
      INSERT INTO order_items (order_id, service_id, name, code, sage_code, price, qty, delivered_qty, production_stage)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(orderId, svc.id, svc.name, svc.code, svc.sageCode, svc.price, qtyNum, qtyNum, order.production_stage || 'tri');
  }

  res.status(201).json({ order: serializeOrder(order, getItems(orderId)) });
});

// DELETE /api/admin/orders/:id — supprime une commande. Les lignes
// d'articles, hôtels supplémentaires et commentaires liés partent avec
// elle (ON DELETE CASCADE, clés étrangères actives — voir db.js).
router.delete('/orders/:id', (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT id FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });
  db.prepare('DELETE FROM orders WHERE id = ?').run(orderId);
  res.json({ ok: true });
});

// GET /api/admin/settings
router.get('/settings', (req, res) => {
  const admin = getAdminRow();
  res.json({ deliveryEmail: admin?.delivery_email || '' });
});

// PUT /api/admin/settings
router.put('/settings', (req, res) => {
  const { deliveryEmail } = req.body || {};
  db.prepare('UPDATE admin SET delivery_email = ? WHERE id = 1').run(deliveryEmail || null);
  res.json({ ok: true });
});

// POST /api/admin/orders/:id/delivery-note — génère (et tente d'envoyer) le bon de livraison
router.post('/orders/:id/delivery-note', async (req, res) => {
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) return res.status(404).json({ error: 'Commande introuvable.' });

  const items = getItems(order.id);
  const orderWithItems = { ...order, items };
  const text = buildDeliveryNoteText(orderWithItems);
  const admin = getAdminRow();
  const to = admin?.delivery_email;

  if (!to) {
    return res.json({ sent: false, reason: 'no_email', text });
  }
  if (!isConfigured()) {
    return res.json({ sent: false, reason: 'smtp_not_configured', text, to });
  }

  try {
    const [html, pdfBuffer] = await Promise.all([
      Promise.resolve(buildDeliveryNoteHtml(orderWithItems)),
      buildDeliveryNotePdf(orderWithItems),
    ]);
    await sendMail({
      to,
      subject: `Bon de livraison ${order.ticket}`,
      text,
      html,
      attachments: [{
        filename: `bon-livraison-${order.ticket}.pdf`,
        content: pdfBuffer,
        contentType: 'application/pdf',
      }],
    });
    res.json({ sent: true, to, text });
  } catch (err) {
    console.error('Échec envoi email :', err.message);
    res.status(502).json({ sent: false, reason: 'send_failed', text, to, error: err.message });
  }
});

module.exports = router;
