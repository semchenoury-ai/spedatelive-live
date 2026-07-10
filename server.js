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
  console.log("✅ Base de données prête.");
}

// util : renvoie l'utilisateur "public" (sans le hash du mot de passe)
function publicUser(u) {
  if (!u) return null;
  return { id:u.id, pseudo:u.pseudo, email:u.email, age:u.age, photo:u.photo,
           genre:u.genre, pref:u.pref, origine:u.origine, cible:u.cible, settings:u.settings||{} };
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
    try{
      const hash=await bcrypt.hash(password,10);
      const r=await pool.query(
        "INSERT INTO users(pseudo,email,pass_hash) VALUES($1,$2,$3) RETURNING *",
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
function compatible(a, b) {
  if (a.id === b.id) return false;
  const aWantsB = a.pref === "tous" || a.pref === b.genre;
  const bWantsA = b.pref === "tous" || b.pref === a.genre;
  if (!aWantsB || !bWantsA) return false;
  if (a.pays !== "all" && a.pays !== b.origine) return false;
  if (b.pays !== "all" && b.pays !== a.origine) return false;
  return true;
}
function publicInfo(u){ return { genre:u.genre, origine:u.origine, pseudo:u.pseudo||"" }; }
function tryMatch(user){
  for (let i=0;i<waiting.length;i++){ const other=waiting[i];
    if (compatible(user, other)){
      waiting.splice(i,1); waiting=waiting.filter(u=>u.id!==user.id);
      user.room=other; other.room=user;
      send(user.ws,{type:"matched",initiator:true, peer:publicInfo(other)});
      send(other.ws,{type:"matched",initiator:false, peer:publicInfo(user)});
      return true;
    }
  }
  return false;
}
function requeue(user){ waiting=waiting.filter(u=>u.id!==user.id); if(!tryMatch(user)){ waiting.push(user); send(user.ws,{type:"waiting",count:waiting.length}); } }
function leaveRoom(user, notify){ const peer=user.room; user.room=null; if(peer){ peer.room=null; if(notify && peer.ws.readyState===1){ send(peer.ws,{type:"peer-left"}); requeue(peer); } } }
wss.on("connection",(ws)=>{
  const user={ id:nextId++, ws, room:null };
  ws.on("message",(raw)=>{
    let msg; try{ msg=JSON.parse(raw); }catch(e){ return; }
    if(msg.type==="join"){ user.genre=msg.genre; user.pref=msg.pref; user.origine=msg.origine||"all"; user.pays=msg.pays||"all"; user.pseudo=msg.pseudo||""; requeue(user); }
    else if(msg.type==="signal"){ if(user.room && user.room.ws.readyState===1) send(user.room.ws,{type:"signal",data:msg.data}); }
    else if(msg.type==="next"){ leaveRoom(user,true); requeue(user); }
    else if(msg.type==="stop"){ leaveRoom(user,true); waiting=waiting.filter(u=>u.id!==user.id); }
  });
  ws.on("close",()=>{ leaveRoom(user,true); waiting=waiting.filter(u=>u.id!==user.id); });
});

initDB().catch(e=>console.error("initDB:",e)).finally(()=>{
  server.listen(PORT, ()=>console.log("SpeeDateLive server on :"+PORT+" (db:"+hasDB+")"));
});
