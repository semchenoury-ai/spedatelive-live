// SpeeDateLive — serveur de matchmaking + signalisation WebRTC
// De vrais utilisateurs sont mis en relation en vidéo selon leurs critères.
const http = require("http");
const fs = require("fs");
const path = require("path");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;
const PUB = __dirname;  // les fichiers (index.html) sont à la racine

// --- Serveur HTTP : sert les fichiers du dossier public ---
const server = http.createServer((req, res) => {
  let url = req.url.split("?")[0];
  if (url === "/") url = "/index.html";
  const file = path.join(PUB, path.normalize(url).replace(/^(\.\.[/\\])+/, ""));
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    const ext = path.extname(file).toLowerCase();
    const types = { ".html":"text/html", ".js":"text/javascript", ".css":"text/css", ".svg":"image/svg+xml", ".png":"image/png", ".ico":"image/x-icon" };
    res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream" });
    res.end(data);
  });
});

// --- WebSocket : matchmaking + relais de signalisation ---
const wss = new WebSocketServer({ server });
let waiting = [];      // utilisateurs en attente
let nextId = 1;

function send(ws, obj) { try { ws.send(JSON.stringify(obj)); } catch (e) {} }

// deux personnes sont compatibles si leurs préférences se correspondent mutuellement
function compatible(a, b) {
  if (a.id === b.id) return false;
  // genre recherché
  const aWantsB = a.pref === "tous" || a.pref === b.genre;
  const bWantsA = b.pref === "tous" || b.pref === a.genre;
  if (!aWantsB || !bWantsA) return false;
  // pays (si l'un vise un pays précis, l'autre doit être de ce pays ; "all" = peu importe)
  if (a.pays !== "all" && a.pays !== b.origine) return false;
  if (b.pays !== "all" && b.pays !== a.origine) return false;
  return true;
}

function tryMatch(user) {
  for (let i = 0; i < waiting.length; i++) {
    const other = waiting[i];
    if (compatible(user, other)) {
      waiting.splice(i, 1);                 // retire l'autre de la file
      waiting = waiting.filter(u => u.id !== user.id); // et soi-même
      const room = "r" + user.id + "_" + other.id;
      user.room = other; other.room = user;
      // on désigne un "initiateur" pour lancer l'appel WebRTC
      send(user.ws, { type: "matched", initiator: true,  peer: publicInfo(other) });
      send(other.ws, { type: "matched", initiator: false, peer: publicInfo(user) });
      return true;
    }
  }
  return false;
}

function publicInfo(u) { return { genre: u.genre, origine: u.origine, pseudo: u.pseudo || "" }; }

function leaveRoom(user, notify) {
  const peer = user.room;
  user.room = null;
  if (peer) {
    peer.room = null;
    if (notify && peer.ws.readyState === 1) {
      send(peer.ws, { type: "peer-left" });
      requeue(peer);            // le partenaire retourne dans la file
    }
  }
}

function requeue(user) {
  waiting = waiting.filter(u => u.id !== user.id);
  if (!tryMatch(user)) { waiting.push(user); send(user.ws, { type: "waiting", count: waiting.length }); }
}

wss.on("connection", (ws) => {
  const user = { id: nextId++, ws, room: null };

  ws.on("message", (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch (e) { return; }

    if (msg.type === "join") {
      user.genre = msg.genre; user.pref = msg.pref;
      user.origine = msg.origine || "all"; user.pays = msg.pays || "all";
      user.pseudo = msg.pseudo || "";
      requeue(user);
    }
    else if (msg.type === "signal") {           // relais WebRTC (offer/answer/ice)
      if (user.room && user.room.ws.readyState === 1) send(user.room.ws, { type: "signal", data: msg.data });
    }
    else if (msg.type === "next") {             // passer à quelqu'un d'autre
      leaveRoom(user, true);
      requeue(user);
    }
    else if (msg.type === "stop") {             // quitter la file
      leaveRoom(user, true);
      waiting = waiting.filter(u => u.id !== user.id);
    }
  });

  ws.on("close", () => {
    leaveRoom(user, true);
    waiting = waiting.filter(u => u.id !== user.id);
  });
});

server.listen(PORT, () => console.log("SpeeDateLive live server on :" + PORT));
