// SpeeDateLive — serveur : fichiers + comptes réels (PostgreSQL) + matchmaking WebRTC
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 3000;
const PUB = __dirname;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

// --- Stripe (paiements) ---
const stripe = process.env.STRIPE_SECRET_KEY ? require("stripe")(process.env.STRIPE_SECRET_KEY) : null;
// Catalogue produits : nom, prix en centimes, effet sur le portefeuille
const PRODUCTS = {
  jetons5:  { name:"5 jetons SpeeDateLive",  amount:299, tokens:5 },
  jetons10: { name:"10 jetons SpeeDateLive", amount:399, tokens:10 },
  boost5:   { name:"Boost 5 minutes",        amount:199, boost:5 },
  boost25:  { name:"Boost 25 minutes",       amount:399, boost:25 },
  ville:    { name:"Débloquer la ville",     amount:199, premium:true },
  vip:      { name:"Pack VIP SpeeDateLive",  amount:799, vip:true, premium:true, tokens:20, boost:25 }
};

// --- Base de données (Neon PostgreSQL) ---
const hasDB = !!process.env.DATABASE_URL;
const pool = hasDB ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5
}) : null;

async function initDB() {
  if (!pool) { console.warn("⚠️  DATABASE_URL absente — comptes désactivés."); return; }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id       SERIAL PRIMARY KEY,
      pseudo   TEXT,
      email    TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      age      INT,
      photo    TEXT,
      genre    TEXT,
      pref     TEXT,
      origine  TEXT,
      cible    TEXT,
      settings JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT now()
    );`);
  // Portefeuille (jetons / VIP / boost) — ajout de colonnes si absentes
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens INT DEFAULT 3;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS premium BOOLEAN DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vip BOOLEAN DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS free_boost INT DEFAULT 0;`);
  // Modération : consentement 18+ et suspension de compte
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS agree18 BOOLEAN DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT false;`);
  // Signalements
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      reporter_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      UNIQUE (reporter_id, reported_id)
    );`);
  // Achats payés (idempotence : on ne crédite qu'une fois par session Stripe)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS purchases (
      session_id TEXT PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      product TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );`);
  // Coups de cœur (un like par sens). Match mutuel = deux likes croisés.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS likes (
      liker_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      liked_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT now(),
      PRIMARY KEY (liker_id, liked_id)
    );`);
  // Messages entre membres
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      from_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_id   INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text    TEXT NOT NULL,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(from_id, to_id, created_at);`);
  // Blocages
  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocks (
      blocker_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      blocked_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT now(),
      PRIMARY KEY (blocker_id, blocked_id)
    );`);
  console.log("✅ Base de données prête.");
}

// util : renvoie l'utilisateur "public" (sans le hash du mot de passe)
function publicUser(u) {
  if (!u) return null;
  return { id:u.id, pseudo:u.pseudo, email:u.email, age:u.age, photo:u.photo,
           genre:u.genre, pref:u.pref, origine:u.origine, cible:u.cible, settings:u.settings||{},
           tokens:(u.tokens==null?3:u.tokens), premium:!!u.premium, vip:!!u.vip, free_boost:u.free_boost||0 };
}
// Applique un produit acheté au portefeuille de l'utilisateur (en base)
async function applyProduct(uid, product){
  const p = PRODUCTS[product]; if(!p) return;
  const sets=[]; const vals=[]; let i=1;
  if(p.tokens){ sets.push("tokens=COALESCE(tokens,3)+$"+(i++)); vals.push(p.tokens); }
  if(p.boost){ sets.push("free_boost=COALESCE(free_boost,0)+$"+(i++)); vals.push(p.boost); }
  if(p.premium){ sets.push("premium=true"); }
  if(p.vip){ sets.push("vip=true"); }
  if(!sets.length) return;
  vals.push(uid);
  await pool.query("UPDATE users SET "+sets.join(",")+" WHERE id=$"+i, vals);
}
function makeToken(u){ return jwt.sign({ uid:u.id }, JWT_SECRET, { expiresIn:"60d" }); }

// --- Helpers HTTP ---
function sendJSON(res, code, obj){ res.writeHead(code, {"Content-Type":"application/json"}); res.end(JSON.stringify(obj)); }
function readBody(req){
  return new Promise((resolve)=>{
    let data=""; req.on("data",c=>{ data+=c; if(data.length>3e6) req.destroy(); });
    req.on("end",()=>{ try{ resolve(JSON.parse(data||"{}")); }catch(e){ resolve({}); } });
  });
}
async function userFromAuth(req){
  const h=req.headers["authorization"]||""; const m=h.match(/^Bearer\s+(.+)$/i);
  if(!m || !pool) return null;
  try{ const {uid}=jwt.verify(m[1], JWT_SECRET);
    const r=await pool.query("SELECT * FROM users WHERE id=$1",[uid]); return r.rows[0]||null;
  }catch(e){ return null; }
}
const validEmail = (e)=> typeof e==="string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

// --- API des comptes ---
async function handleAPI(req, res, url){
  if(!pool){ return sendJSON(res,503,{error:"Base de données non configurée."}); }

  // Inscription
  if(url==="/api/signup" && req.method==="POST"){
    const b=await readBody(req);
    const pseudo=(b.pseudo||"").trim(), email=(b.email||"").trim().toLowerCase(), password=b.password||"";
    if(!pseudo) return sendJSON(res,400,{error:"Choisis un pseudo."});
    if(!validEmail(email)) return sendJSON(res,400,{error:"Adresse e-mail invalide."});
    if(password.length<6) return sendJSON(res,400,{error:"Mot de passe : au moins 6 caractères."});
    if(b.agree18!==true) return sendJSON(res,400,{error:"Tu dois certifier avoir 18 ans ou plus et accepter les règles."});
    try{
      const hash=await bcrypt.hash(password,10);
      const r=await pool.query(
        "INSERT INTO users(pseudo,email,pass_hash,agree18) VALUES($1,$2,$3,true) RETURNING *",
        [pseudo,email,hash]);
      const u=r.rows[0];
      return sendJSON(res,200,{ token:makeToken(u), user:publicUser(u) });
    }catch(e){
      if(e.code==="23505") return sendJSON(res,409,{error:"Un compte existe déjà avec cet e-mail."});
      console.error(e); return sendJSON(res,500,{error:"Erreur serveur."});
    }
  }

  // Connexion
  if(url==="/api/login" && req.method==="POST"){
    const b=await readBody(req);
    const email=(b.email||"").trim().toLowerCase(), password=b.password||"";
    const r=await pool.query("SELECT * FROM users WHERE email=$1",[email]);
    const u=r.rows[0];
    if(!u) return sendJSON(res,401,{error:"E-mail ou mot de passe incorrect."});
    const ok=await bcrypt.compare(password, u.pass_hash);
    if(!ok) return sendJSON(res,401,{error:"E-mail ou mot de passe incorrect."});
    if(u.banned) return sendJSON(res,403,{error:"Ce compte a été suspendu pour non-respect des règles."});
    return sendJSON(res,200,{ token:makeToken(u), user:publicUser(u) });
  }

  // Profil courant (restaure la session)
  if(url==="/api/me" && req.method==="GET"){
    const u=await userFromAuth(req);
    if(!u) return sendJSON(res,401,{error:"Non connecté."});
    return sendJSON(res,200,{ user:publicUser(u) });
  }

  // Mise à jour du profil
  if(url==="/api/profile" && req.method==="POST"){
    const u=await userFromAuth(req);
    if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req);
    const fields=["pseudo","age","photo","genre","pref","origine","cible","settings"];
    const sets=[], vals=[]; let i=1;
    for(const f of fields){ if(b[f]!==undefined){ sets.push(f+"=$"+i); vals.push(f==="settings"?JSON.stringify(b[f]):b[f]); i++; } }
    if(!sets.length) return sendJSON(res,200,{ user:publicUser(u) });
    vals.push(u.id);
    const r=await pool.query("UPDATE users SET "+sets.join(",")+" WHERE id=$"+i+" RETURNING *",vals);
    return sendJSON(res,200,{ user:publicUser(r.rows[0]) });
  }

  // Changer le mot de passe
  if(url==="/api/password" && req.method==="POST"){
    const u=await userFromAuth(req);
    if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req);
    if((b.password||"").length<6) return sendJSON(res,400,{error:"Au moins 6 caractères."});
    const hash=await bcrypt.hash(b.password,10);
    await pool.query("UPDATE users SET pass_hash=$1 WHERE id=$2",[hash,u.id]);
    return sendJSON(res,200,{ ok:true });
  }

  // ---- Coup de cœur : enregistré + détection du match mutuel ----
  if(url==="/api/like" && req.method==="POST"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req); const other=parseInt(b.otherId,10);
    if(!other || other===u.id) return sendJSON(res,400,{error:"Cible invalide."});
    await pool.query("INSERT INTO likes(liker_id,liked_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[u.id,other]);
    const r=await pool.query("SELECT 1 FROM likes WHERE liker_id=$1 AND liked_id=$2",[other,u.id]);
    return sendJSON(res,200,{ mutual: r.rowCount>0 });
  }

  // ---- Mes rencontres : matchs mutuels + "ils t'ont mis un cœur" ----
  if(url==="/api/relations" && req.method==="GET"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const matches=await pool.query(
      `SELECT us.id,us.pseudo,us.genre,us.origine,us.age,us.photo
       FROM likes l1 JOIN likes l2 ON l1.liked_id=l2.liker_id AND l1.liker_id=l2.liked_id
       JOIN users us ON us.id=l1.liked_id
       WHERE l1.liker_id=$1 AND NOT EXISTS(SELECT 1 FROM blocks b WHERE b.blocker_id=$1 AND b.blocked_id=us.id)`,[u.id]);
    const likedMe=await pool.query(
      `SELECT us.id,us.pseudo,us.genre,us.origine,us.age,us.photo
       FROM likes l JOIN users us ON us.id=l.liker_id
       WHERE l.liked_id=$1
         AND NOT EXISTS(SELECT 1 FROM likes l2 WHERE l2.liker_id=$1 AND l2.liked_id=us.id)
         AND NOT EXISTS(SELECT 1 FROM blocks b WHERE b.blocker_id=$1 AND b.blocked_id=us.id)`,[u.id]);
    return sendJSON(res,200,{ matches:matches.rows, likedMe:likedMe.rows });
  }

  // ---- Conversations (dernière ligne + non-lus) ----
  if(url==="/api/conversations" && req.method==="GET"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const rows=await pool.query(
      `WITH convo AS (
         SELECT CASE WHEN from_id=$1 THEN to_id ELSE from_id END AS other, text, created_at, to_id, read_at
         FROM messages WHERE from_id=$1 OR to_id=$1)
       SELECT c.other AS id, us.pseudo, us.genre, us.origine, us.photo,
              (SELECT text FROM convo c2 WHERE c2.other=c.other ORDER BY created_at DESC LIMIT 1) AS last_text,
              max(c.created_at) AS last_at,
              count(*) FILTER (WHERE c.to_id=$1 AND c.read_at IS NULL) AS unread
       FROM convo c JOIN users us ON us.id=c.other
       WHERE NOT EXISTS(SELECT 1 FROM blocks b WHERE b.blocker_id=$1 AND b.blocked_id=c.other)
       GROUP BY c.other, us.pseudo, us.genre, us.origine, us.photo
       ORDER BY last_at DESC`,[u.id]);
    return sendJSON(res,200,{ conversations:rows.rows });
  }

  // ---- Fil de messages avec une personne (marque comme lus) ----
  if(url==="/api/messages" && req.method==="GET"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const mm=(req.url.split("?")[1]||"").match(/with=(\d+)/); const other=mm?parseInt(mm[1],10):0;
    if(!other) return sendJSON(res,400,{error:"Paramètre with manquant."});
    const rows=await pool.query(
      `SELECT id,from_id,to_id,text,created_at FROM messages
       WHERE (from_id=$1 AND to_id=$2) OR (from_id=$2 AND to_id=$1) ORDER BY created_at ASC`,[u.id,other]);
    await pool.query("UPDATE messages SET read_at=now() WHERE to_id=$1 AND from_id=$2 AND read_at IS NULL",[u.id,other]);
    return sendJSON(res,200,{ messages:rows.rows, meId:u.id });
  }

  // ---- Envoyer un message (interdit si blocage) ----
  if(url==="/api/message" && req.method==="POST"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req); const to=parseInt(b.toId,10); const text=(b.text||"").trim();
    if(!to||to===u.id) return sendJSON(res,400,{error:"Destinataire invalide."});
    if(!text) return sendJSON(res,400,{error:"Message vide."});
    const blk=await pool.query("SELECT 1 FROM blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)",[u.id,to]);
    if(blk.rowCount>0) return sendJSON(res,403,{error:"Impossible : blocage."});
    const r=await pool.query("INSERT INTO messages(from_id,to_id,text) VALUES($1,$2,$3) RETURNING id,created_at",[u.id,to,text.slice(0,2000)]);
    return sendJSON(res,200,{ id:r.rows[0].id, created_at:r.rows[0].created_at });
  }

  // ---- Bloquer / débloquer / liste ----
  if(url==="/api/block" && req.method==="POST"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req); const id=parseInt(b.id,10); if(!id||id===u.id) return sendJSON(res,400,{error:"Cible invalide."});
    await pool.query("INSERT INTO blocks(blocker_id,blocked_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[u.id,id]);
    return sendJSON(res,200,{ ok:true });
  }
  if(url==="/api/unblock" && req.method==="POST"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req); const id=parseInt(b.id,10);
    await pool.query("DELETE FROM blocks WHERE blocker_id=$1 AND blocked_id=$2",[u.id,id]);
    return sendJSON(res,200,{ ok:true });
  }
  if(url==="/api/blocks" && req.method==="GET"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const rows=await pool.query("SELECT us.id,us.pseudo,us.genre,us.origine,us.photo FROM blocks b JOIN users us ON us.id=b.blocked_id WHERE b.blocker_id=$1",[u.id]);
    return sendJSON(res,200,{ blocked:rows.rows });
  }

  // ---- Signalement (modération) : stocke + bloque + suspend automatiquement ----
  if(url==="/api/report" && req.method==="POST"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req); const rid=parseInt(b.reportedId,10); const reason=(b.reason||"").slice(0,300);
    if(!rid||rid===u.id) return sendJSON(res,400,{error:"Cible invalide."});
    await pool.query("INSERT INTO reports(reporter_id,reported_id,reason) VALUES($1,$2,$3) ON CONFLICT (reporter_id,reported_id) DO UPDATE SET reason=EXCLUDED.reason, created_at=now()",[u.id,rid,reason]);
    const c=await pool.query("SELECT count(*)::int AS n FROM reports WHERE reported_id=$1",[rid]);
    if(c.rows[0].n>=3){ await pool.query("UPDATE users SET banned=true WHERE id=$1",[rid]); }
    await pool.query("INSERT INTO blocks(blocker_id,blocked_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[u.id,rid]);
    return sendJSON(res,200,{ ok:true, suspended: c.rows[0].n>=3 });
  }

  // ---- Portefeuille (jetons/VIP/boost) : charger / sauvegarder ----
  if(url==="/api/wallet" && req.method==="GET"){
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    return sendJSON(res,200,{ tokens:(u.tokens==null?3:u.tokens), premium:!!u.premium, vip:!!u.vip, free_boost:u.free_boost||0 });
  }
  if(url==="/api/wallet" && req.method==="POST"){
    // sauvegarde la DÉPENSE côté compte (jetons dépensés, boost activé…) pour la persistance multi-appareils
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req);
    const sets=[], vals=[]; let i=1;
    if(typeof b.tokens==="number"){ sets.push("tokens=$"+(i++)); vals.push(Math.max(0,Math.floor(b.tokens))); }
    if(typeof b.free_boost==="number"){ sets.push("free_boost=$"+(i++)); vals.push(Math.max(0,Math.floor(b.free_boost))); }
    if(!sets.length) return sendJSON(res,200,{ ok:true });
    vals.push(u.id);
    await pool.query("UPDATE users SET "+sets.join(",")+" WHERE id=$"+i, vals);
    return sendJSON(res,200,{ ok:true });
  }

  // ---- Créer une session de paiement Stripe ----
  if(url==="/api/checkout" && req.method==="POST"){
    if(!stripe) return sendJSON(res,503,{error:"Paiement non configuré (clé Stripe manquante)."});
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const b=await readBody(req); const product=b.product; const P=PRODUCTS[product];
    if(!P) return sendJSON(res,400,{error:"Produit inconnu."});
    const base = (req.headers["x-forwarded-proto"]||"https")+"://"+req.headers.host;
    try{
      const session=await stripe.checkout.sessions.create({
        mode:"payment",
        line_items:[{ price_data:{ currency:"eur", product_data:{name:P.name}, unit_amount:P.amount }, quantity:1 }],
        success_url: base+"/?paid="+product+"&session_id={CHECKOUT_SESSION_ID}",
        cancel_url: base+"/?canceled=1",
        client_reference_id:String(u.id),
        metadata:{ uid:String(u.id), product }
      });
      return sendJSON(res,200,{ url:session.url });
    }catch(e){ console.error("stripe:",e.message); return sendJSON(res,500,{error:"Erreur paiement."}); }
  }

  // ---- Confirmer un paiement (au retour de Stripe) et créditer une seule fois ----
  if(url==="/api/checkout/confirm" && req.method==="GET"){
    if(!stripe) return sendJSON(res,503,{error:"Paiement non configuré."});
    const u=await userFromAuth(req); if(!u) return sendJSON(res,401,{error:"Non connecté."});
    const mm=(req.url.split("?")[1]||"").match(/session_id=([^&]+)/); const sid=mm?decodeURIComponent(mm[1]):"";
    if(!sid) return sendJSON(res,400,{error:"session_id manquant."});
    try{
      const s=await stripe.checkout.sessions.retrieve(sid);
      if(s.payment_status!=="paid") return sendJSON(res,200,{ paid:false });
      const uid=parseInt(s.metadata&&s.metadata.uid,10); const product=s.metadata&&s.metadata.product;
      if(uid!==u.id) return sendJSON(res,403,{error:"Session non reconnue."});
      const ins=await pool.query("INSERT INTO purchases(session_id,user_id,product) VALUES($1,$2,$3) ON CONFLICT(session_id) DO NOTHING RETURNING 1",[sid,u.id,product]);
      if(ins.rowCount>0){ await applyProduct(u.id, product); }
      const r=await pool.query("SELECT tokens,premium,vip,free_boost FROM users WHERE id=$1",[u.id]);
      const w=r.rows[0];
      return sendJSON(res,200,{ paid:true, product, wallet:{ tokens:w.tokens, premium:w.premium, vip:w.vip, free_boost:w.free_boost } });
    }catch(e){ console.error("confirm:",e.message); return sendJSON(res,500,{error:"Erreur de confirmation."}); }
  }

  return sendJSON(res,404,{error:"Route inconnue."});
}

// --- Serveur HTTP : API + fichiers statiques ---
const server = http.createServer(async (req, res) => {
  let url = req.url.split("?")[0];
  if(url==="/health") return sendJSON(res,200,{ ok:true, db:hasDB });
  if(url.startsWith("/api/")){ try{ return await handleAPI(req,res,url); }catch(e){ console.error(e); return sendJSON(res,500,{error:"Erreur serveur."}); } }

  if (url === "/") url = "/index.html";
  const file = path.join(PUB, path.normalize(url).replace(/^(\.\.[/\\])+/, ""));
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    const ext = path.extname(file).toLowerCase();
    const types = { ".html":"text/html", ".js":"text/javascript", ".css":"text/css", ".svg":"image/svg+xml", ".png":"image/png", ".ico":"image/x-icon", ".json":"application/json" };
    res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream" });
    res.end(data);
  });
});

// --- WebSocket : matchmaking + relais de signalisation WebRTC ---
const wss = new WebSocketServer({ server });
let waiting = [];
let nextId = 1;
function send(ws, obj) { try { ws.send(JSON.stringify(obj)); } catch (e) {} }
function ageOK(pref, age) {
  if (!pref) return true;                 // pas de filtre d'âge
  age = parseInt(age, 10); if (!age) return true;  // âge inconnu → on laisse passer
  if (pref === "18-30") return age >= 18 && age <= 30;
  if (pref === "30+")   return age >= 30;
  return true;
}
// Deux personnes sont compatibles si TOUS leurs critères mutuels sont respectés
function compatible(a, b) {
  if (a.id === b.id) return false;
  // genre recherché (mutuel)
  const aWantsB = a.pref === "tous" || a.pref === b.genre;
  const bWantsA = b.pref === "tous" || b.pref === a.genre;
  if (!aWantsB || !bWantsA) return false;
  // pays ("all" = peu importe)
  if (a.pays !== "all" && a.pays !== b.origine) return false;
  if (b.pays !== "all" && b.pays !== a.origine) return false;
  // âge (filtre VIP : 18-30 / 30+)
  if (!ageOK(a.agePref, b.age)) return false;
  if (!ageOK(b.agePref, a.age)) return false;
  // couleur de cheveux (filtre VIP) — on ne bloque que si l'info de l'autre est connue
  if (a.hairPref && b.hair && a.hairPref !== b.hair) return false;
  if (b.hairPref && a.hair && b.hairPref !== a.hair) return false;
  // ville visée (filtre VIP)
  if (a.villeCible && b.ville && a.villeCible !== b.ville) return false;
  if (b.villeCible && a.ville && b.villeCible !== a.ville) return false;
  // blocage : on ne se recroise jamais si l'un a bloqué l'autre
  if (a.blocked && b.uid && a.blocked.indexOf(b.uid) !== -1) return false;
  if (b.blocked && a.uid && b.blocked.indexOf(a.uid) !== -1) return false;
  return true;
}
function publicInfo(u){ return { uid:u.uid||null, genre:u.genre, origine:u.origine, pseudo:u.pseudo||"", age:u.age||null, hair:u.hair||null, ville:u.ville||null }; }
// Cherche un partenaire compatible : les personnes BOOSTÉES passent en priorité
function findMatchIndex(user){
  for (let i=0;i<waiting.length;i++){ if (waiting[i].boost && compatible(user, waiting[i])) return i; }
  for (let i=0;i<waiting.length;i++){ if (compatible(user, waiting[i])) return i; }
  return -1;
}
function tryMatch(user){
  const i = findMatchIndex(user);
  if (i < 0) return false;
  const other = waiting[i];
  waiting.splice(i,1); waiting = waiting.filter(u=>u.id!==user.id);
  user.room = other; other.room = user;
  send(user.ws,{type:"matched",initiator:true, peer:publicInfo(other)});
  send(other.ws,{type:"matched",initiator:false, peer:publicInfo(user)});
  return true;
}
function requeue(user){ waiting=waiting.filter(u=>u.id!==user.id); if(!tryMatch(user)){ waiting.push(user); send(user.ws,{type:"waiting",count:waiting.length}); } }
function leaveRoom(user, notify){ const peer=user.room; user.room=null; if(peer){ peer.room=null; if(notify && peer.ws.readyState===1){ send(peer.ws,{type:"peer-left"}); requeue(peer); } } }
const clients = new Map();   // id -> user, pour retrouver la dernière personne (fonction « Revenir »)
wss.on("connection",(ws)=>{
  const user={ id:nextId++, ws, room:null, lastPeerId:null };
  clients.set(user.id, user);
  ws.on("message",async (raw)=>{
    let msg; try{ msg=JSON.parse(raw); }catch(e){ return; }
    if(msg.type==="join"){
      user.genre=msg.genre; user.pref=msg.pref;
      user.origine=msg.origine||"all"; user.pays=msg.pays||"all";
      user.age=msg.age||null; user.agePref=msg.agePref||null;
      user.hair=msg.hair||null; user.hairPref=msg.hairPref||null;
      user.ville=msg.ville||null; user.villeCible=msg.villeCible||null;
      user.boost=!!msg.boost;
      user.uid=msg.uid||null;            // relie la connexion live au compte
      user.blocked=Array.isArray(msg.blocked)?msg.blocked:[];   // uids bloqués
      user.pseudo=msg.pseudo||"";
      // modération : un compte suspendu ne peut pas entrer dans le live
      if(pool && user.uid){
        try{ const r=await pool.query("SELECT banned FROM users WHERE id=$1",[user.uid]);
          if(r.rows[0] && r.rows[0].banned){ send(user.ws,{type:"banned"}); return; } }catch(e){}
      }
      requeue(user);
    }
    else if(msg.type==="boost"){ user.boost = !!msg.on; }  // active/désactive la priorité
    else if(msg.type==="blocklist"){ user.blocked = Array.isArray(msg.blocked)?msg.blocked:[]; }  // maj des blocages
    else if(msg.type==="signal"){ if(user.room && user.room.ws.readyState===1) send(user.room.ws,{type:"signal",data:msg.data}); }
    else if(msg.type==="next"){
      if(user.room) user.lastPeerId = user.room.id;   // on retient la personne qu'on quitte
      leaveRoom(user,true); requeue(user);
    }
    else if(msg.type==="recall"){
      // « Revenir » : on tente de reconnecter avec la dernière personne SI elle est encore libre
      const peer = clients.get(user.lastPeerId);
      if(peer && peer!==user && peer.ws.readyState===1 && !peer.room){
        leaveRoom(user,true);                         // quitte la situation actuelle
        waiting = waiting.filter(u=>u.id!==user.id && u.id!==peer.id);
        user.room=peer; peer.room=user;
        send(user.ws,{type:"matched",initiator:true, peer:publicInfo(peer)});
        send(peer.ws,{type:"matched",initiator:false, peer:publicInfo(user)});
      } else {
        send(user.ws,{type:"recall-failed"});         // → le client rembourse le jeton
      }
    }
    else if(msg.type==="stop"){ leaveRoom(user,true); waiting=waiting.filter(u=>u.id!==user.id); }
  });
  ws.on("close",()=>{ leaveRoom(user,true); waiting=waiting.filter(u=>u.id!==user.id); clients.delete(user.id); });
});

initDB().catch(e=>console.error("initDB:",e)).finally(()=>{
  server.listen(PORT, ()=>console.log("SpeeDateLive server on :"+PORT+" (db:"+hasDB+")"));
});
