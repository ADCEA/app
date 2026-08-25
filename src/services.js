// Catalogue d'articles — désormais géré en base de données (table
// `articles`), modifiable depuis Administration → Gestion des articles.
//
// IMPORTANT : ce sont des FONCTIONS, pas des valeurs figées. Comme le
// catalogue peut changer à tout moment depuis l'admin, chaque fichier qui
// en a besoin doit appeler getServices()/getServicesById()/etc. au moment
// de l'utiliser (dans le corps d'une route), PAS une fois pour toutes en
// haut du fichier avec un `const { X } = require(...)` — sinon la valeur
// resterait celle du démarrage du serveur.
//
// "category" sert uniquement à regrouper l'affichage côté frontend.

const db = require('./db');

const CATEGORIES = [
  { id: 'lit', label: 'Linge de lit' },
  { id: 'toilette', label: 'Linge de toilette' },
  { id: 'service', label: 'Entretien & service' },
];

function getServices() {
  return db.prepare('SELECT id, name, code, sage_code as sageCode, price, category FROM articles ORDER BY category, name').all();
}

function getServicesById() {
  return Object.fromEntries(getServices().map(s => [s.id, s]));
}

function getServicesBySageCode() {
  return Object.fromEntries(getServices().map(s => [s.sageCode.toUpperCase(), s]));
}

// Catalogue filtré pour UN client précis : s'il a des articles attribués
// (table client_articles), il ne voit que ceux-là ; sinon, tout le
// catalogue par défaut (comportement rétrocompatible).
function getServicesForClient(clientId) {
  if (!clientId) return getServices();
  const hasAssignment = db.prepare('SELECT 1 FROM client_articles WHERE client_id = ? LIMIT 1').get(clientId);
  if (!hasAssignment) return getServices();
  return db.prepare(`
    SELECT a.id, a.name, a.code, a.sage_code as sageCode, a.price, a.category
    FROM articles a
    JOIN client_articles ca ON ca.article_id = a.id
    WHERE ca.client_id = ?
    ORDER BY a.category, a.name
  `).all(clientId);
}

module.exports = { getServices, getServicesById, getServicesBySageCode, getServicesForClient, CATEGORIES };
