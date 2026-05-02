const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const EVOLUTION_API_URL = (process.env.EVOLUTION_API_URL || '').replace(/\/$/, '');
const EVOLUTION_API_KEY = process.env.EVOLUTION_API_KEY || '';
const EVOLUTION_INSTANCES = (process.env.EVOLUTION_INSTANCES || '')
  .split(',').map((n) => n.trim()).filter(Boolean);
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const SESSION_SECRET = process.env.CRM_SESSION_SECRET || WEBHOOK_SECRET || 'change-me';
const ADMIN_USER = process.env.CRM_ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.CRM_ADMIN_PASSWORD || '';
const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || '';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'crm.json');
const SYNC_CACHE_TTL = Number(process.env.SYNC_CACHE_TTL_SECONDS || 60) * 1000;

const pgPool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl:
        process.env.PGSSLMODE === 'require' || DATABASE_URL.includes('sslmode=require')
          ? { rejectUnauthorized: false }
          : false,
    })
  : null;

let EVOLUTION_API_KEYS = {};
try {
  EVOLUTION_API_KEYS = process.env.EVOLUTION_API_KEYS_JSON
    ? JSON.parse(process.env.EVOLUTION_API_KEYS_JSON)
    : {};
} catch (_) {}

let CRM_CLIENTS = [];
try {
  CRM_CLIENTS = process.env.CRM_CLIENTS_JSON ? JSON.parse(process.env.CRM_CLIENTS_JSON) : [];
} catch (_) {}

// ─── Write mutex ──────────────────────────────────────────────────────────────
let dbLock = Promise.resolve();
function withDbLock(fn) {
  const next = dbLock.then(fn, fn);
  dbLock = next.then(() => {}, () => {});
  return next;
}

// ─── Sync cache ───────────────────────────────────────────────────────────────
const syncCache = new Map();

function getSyncCache(instanceName) {
  const entry = syncCache.get(instanceName);
  if (!entry) return null;
  if (Date.now() - entry.ts > SYNC_CACHE_TTL) { syncCache.delete(instanceName); return null; }
  return entry.leads;
}

function setSyncCache(instanceName, leads) {
  syncCache.set(instanceName, { ts: Date.now(), leads });
}

function clearSyncCache(instanceName) {
  if (instanceName) syncCache.delete(instanceName);
  else syncCache.clear();
}

// ─── SSE clients ──────────────────────────────────────────────────────────────
const sseClients = new Map();

function sseWrite(res, event, data) {
  try { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); } catch (_) {}
}

function sseNotifyAll(event, data) {
  for (const clients of sseClients.values()) {
    for (const res of clients) sseWrite(res, event, data);
  }
}

function sseNotifyForInstance(instanceName, event, data) {
  for (const [username, clients] of sseClients) {
    const user = activeSessions.get(username);
    if (!user || !canAccessInstance(user, instanceName)) continue;
    for (const res of clients) sseWrite(res, event, data);
  }
}

// Track active sessions for SSE targeting
const activeSessions = new Map();

// ─── Rate limiter ─────────────────────────────────────────────────────────────
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = loginAttempts.get(ip);
  if (!entry || entry.resetAt < now) {
    entry = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    loginAttempts.set(ip, entry);
  }
  entry.count += 1;
  return entry.count <= MAX_LOGIN_ATTEMPTS;
}

function resetRateLimit(ip) { loginAttempts.delete(ip); }

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (entry.resetAt < now) loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000);

// ─── Security headers ─────────────────────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

app.use(express.json({ limit: '10mb' }));

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function parseCookies(header = '') {
  return Object.fromEntries(
    header.split(';').map((p) => p.trim()).filter(Boolean).map((p) => {
      const i = p.indexOf('=');
      return [p.slice(0, i), decodeURIComponent(p.slice(i + 1))];
    }),
  );
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(String(password), salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, passwordHash) {
  const [salt, hash] = String(passwordHash || '').split(':');
  if (!salt || !hash) return false;
  const testHash = crypto.pbkdf2Sync(String(password), salt, 100000, 64, 'sha512').toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(testHash, 'hex'));
  } catch (_) { return false; }
}

function createSession(user) {
  const payload = Buffer.from(JSON.stringify({
    username: user.username,
    name: user.name,
    role: user.role,
    instances: user.instances || [],
    exp: Date.now() + 1000 * 60 * 60 * 12,
  })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function readSession(req) {
  const token = parseCookies(req.headers.cookie || '').crm_session;
  if (!token || !token.includes('.')) return null;
  const [payload, signature] = token.split('.');
  if (signature !== sign(payload)) return null;
  try {
    const user = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!user.exp || user.exp < Date.now()) return null;
    return user;
  } catch (_) { return null; }
}

// ─── Users ────────────────────────────────────────────────────────────────────
async function getUsers() {
  const db = await readDb();
  const users = (CRM_CLIENTS || []).map((c) => ({
    id: c.username, username: c.username, password: c.password,
    name: c.name || c.username, role: 'client',
    instances: Array.isArray(c.instances) ? c.instances : [], source: 'env',
  }));
  for (const u of db.users || []) {
    users.push({
      id: u.id, username: u.username, passwordHash: u.passwordHash,
      name: u.name || u.username, role: 'client',
      instances: Array.isArray(u.instances) ? u.instances : [], source: 'db',
    });
  }
  if (ADMIN_PASSWORD) {
    users.push({
      id: 'admin', username: ADMIN_USER, password: ADMIN_PASSWORD,
      name: 'Administrador', role: 'admin', instances: [], source: 'env',
    });
  }
  return users;
}

function verifyUserLogin(user, password) {
  if (user.passwordHash) return verifyPassword(password, user.passwordHash);
  return user.password === password;
}

async function getClientSummaries() {
  const users = await getUsers();
  return users.filter((u) => u.role === 'client').map((u) => ({
    id: u.id, name: u.name, username: u.username, instances: u.instances, source: u.source,
  }));
}

function requireAuth(req, res, next) {
  const user = readSession(req);
  if (!user) return res.status(401).json({ message: 'Login necessario' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ message: 'Apenas admin pode fazer isso' });
  next();
}

function canAccessInstance(user, instanceName) {
  return user?.role === 'admin' || user?.instances?.includes(instanceName);
}

// ─── Database ─────────────────────────────────────────────────────────────────
function defaultDb() {
  return { leads: {}, messages: {}, users: [], templates: [] };
}

let dbInitialized = false;

async function ensureDb() {
  if (dbInitialized) return;
  if (pgPool) {
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS crm_state (
        id TEXT PRIMARY KEY,
        data JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pgPool.query(
      `INSERT INTO crm_state (id, data) VALUES ('main', $1::jsonb) ON CONFLICT (id) DO NOTHING`,
      [JSON.stringify(defaultDb())],
    );
  } else {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(DB_FILE)) await fsp.writeFile(DB_FILE, JSON.stringify(defaultDb(), null, 2));
  }
  dbInitialized = true;
}

async function readDb() {
  await ensureDb();
  let db;
  if (pgPool) {
    const result = await pgPool.query('SELECT data FROM crm_state WHERE id = $1', ['main']);
    db = result.rows[0]?.data || defaultDb();
  } else {
    db = JSON.parse(await fsp.readFile(DB_FILE, 'utf8'));
  }
  db.leads = db.leads || {};
  db.messages = db.messages || {};
  db.users = Array.isArray(db.users) ? db.users : [];
  db.templates = Array.isArray(db.templates) ? db.templates : [];
  return db;
}

async function writeDb(db) {
  await ensureDb();
  if (pgPool) {
    await pgPool.query(
      `INSERT INTO crm_state (id, data, updated_at) VALUES ('main', $1::jsonb, NOW())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
      [JSON.stringify(db)],
    );
  } else {
    await fsp.writeFile(DB_FILE, JSON.stringify(db, null, 2));
  }
}

// ─── Lead helpers ─────────────────────────────────────────────────────────────
function leadKey(instance, jid) { return `${instance}::${jid}`; }

function splitLeadKey(key) {
  const [instance, ...jidParts] = key.split('::');
  return { instance, jid: jidParts.join('::') };
}

function jidToNumber(jid = '') {
  return String(jid).split('@')[0].replace(/\D/g, '');
}

// ─── fromMe extraction ────────────────────────────────────────────────────────
// Handles: boolean true/false, number 1/0, string "true"/"false", nested key.fromMe
function extractFromMe(raw) {
  const v = raw?.key?.fromMe ?? raw?.fromMe ?? false;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v === 1;
  return String(v) === 'true' || String(v) === '1';
}

// ─── Message normalization ────────────────────────────────────────────────────
// Handles two formats returned by Evolution API:
//   1. Proto/Baileys format: { key: { fromMe, id }, message: { conversation, imageMessage, ... }, messageTimestamp }
//   2. Flat format (v2 newer endpoints): { fromMe, id, body, type, timestamp, fileName, duration }
function normalizeMessage(raw) {
  if (!raw || typeof raw !== 'object') {
    return { fromMe: false, id: null, ts: Math.floor(Date.now() / 1000), text: '', type: 'unknown', title: 'Mensagem', fileName: '', seconds: null };
  }

  const fromMe = extractFromMe(raw);
  const ts = normalizeTimestamp(raw.messageTimestamp || raw.timestamp || raw.createdAt);
  const id = raw.key?.id || raw.id || raw.messageId || null;

  // ── Flat format (has `body` field or simple string `type` without nested `message`) ──
  const hasBody = raw.body !== undefined;
  const hasFlatType = raw.type && typeof raw.type === 'string' && !raw.message;
  if (hasBody || hasFlatType) {
    const rawType = String(raw.type || 'text').toLowerCase();
    const typeMap = {
      text: 'text', conversation: 'text', extendedtextmessage: 'text',
      image: 'image', imagemessage: 'image',
      video: 'video', videomessage: 'video',
      audio: 'audio', audiomessage: 'audio', ptt: 'audio',
      document: 'document', documentmessage: 'document',
      sticker: 'sticker', stickermessage: 'sticker',
      location: 'location', locationmessage: 'location',
      vcard: 'contato', contact: 'contato', contactmessage: 'contato',
      reaction: 'reaction', reactionmessage: 'reaction',
      poll: 'poll', pollcreationmessage: 'poll',
      button: 'button', buttonsresponsemessage: 'button', listresponsemessage: 'button',
      order: 'order', ordermessage: 'order',
    };
    const titleMap = {
      text: 'Mensagem', image: 'Imagem', video: 'Video',
      audio: 'Audio', ptt: 'Audio de voz', document: 'Documento',
      sticker: 'Figurinha', location: 'Localizacao', contato: 'Contato',
      reaction: 'Reacao', poll: 'Enquete', button: 'Botao', order: 'Pedido',
    };
    const type = typeMap[rawType] || 'unknown';
    const title = titleMap[type] || 'Mensagem';
    const text = String(
      raw.body || raw.caption || raw.text ||
      (type !== 'text' ? `${title} recebida` : 'Mensagem sem previa'),
    );
    return { fromMe, id, ts, text, type, title, fileName: String(raw.fileName || raw.title || ''), seconds: raw.duration || raw.seconds || null };
  }

  // ── Proto/Baileys format ──
  const inner = raw.ephemeralMessage?.message || raw.viewOnceMessage?.message ||
    raw.viewOnceMessageV2?.message || raw.documentWithCaptionMessage?.message ||
    raw.message || raw;

  const msg = inner.ephemeralMessage?.message || inner.viewOnceMessage?.message ||
    inner.viewOnceMessageV2?.message || inner.documentWithCaptionMessage?.message || inner;

  const ctx = msg.extendedTextMessage?.contextInfo || {};

  if (msg.conversation) return { fromMe, id, ts, type: 'text', title: 'Mensagem', text: msg.conversation, fileName: '', seconds: null };
  if (msg.extendedTextMessage?.text) return { fromMe, id, ts, type: 'text', title: ctx.quotedMessage ? 'Resposta' : 'Mensagem', text: msg.extendedTextMessage.text, fileName: '', seconds: null };
  if (msg.imageMessage) return { fromMe, id, ts, type: 'image', title: 'Imagem', text: msg.imageMessage.caption || 'Imagem recebida', fileName: msg.imageMessage.fileName || '', seconds: null };
  if (msg.videoMessage) return { fromMe, id, ts, type: 'video', title: 'Video', text: msg.videoMessage.caption || 'Video recebido', fileName: '', seconds: msg.videoMessage.seconds || null };
  if (msg.audioMessage) return { fromMe, id, ts, type: 'audio', title: msg.audioMessage.ptt ? 'Audio de voz' : 'Audio', text: msg.audioMessage.ptt ? 'Audio de voz recebido' : 'Audio recebido', fileName: '', seconds: msg.audioMessage.seconds || null };
  if (msg.documentMessage) { const fn = msg.documentMessage.fileName || 'Documento'; return { fromMe, id, ts, type: 'document', title: 'Documento', text: msg.documentMessage.caption || fn, fileName: fn, seconds: null }; }
  if (msg.stickerMessage) return { fromMe, id, ts, type: 'sticker', title: 'Figurinha', text: 'Figurinha recebida', fileName: '', seconds: null };
  if (msg.contactMessage) return { fromMe, id, ts, type: 'contato', title: 'Contato', text: msg.contactMessage.displayName || 'Contato compartilhado', fileName: '', seconds: null };
  if (msg.contactsArrayMessage) return { fromMe, id, ts, type: 'contato', title: 'Contatos', text: `${msg.contactsArrayMessage.contacts?.length || 0} contatos compartilhados`, fileName: '', seconds: null };
  if (msg.locationMessage) return { fromMe, id, ts, type: 'location', title: 'Localizacao', text: msg.locationMessage.name || msg.locationMessage.address || 'Localizacao compartilhada', fileName: '', seconds: null };
  if (msg.buttonsResponseMessage) return { fromMe, id, ts, type: 'button', title: 'Botao selecionado', text: msg.buttonsResponseMessage.selectedDisplayText || msg.buttonsResponseMessage.selectedButtonId || 'Resposta de botao', fileName: '', seconds: null };
  if (msg.listResponseMessage) return { fromMe, id, ts, type: 'button', title: 'Opcao selecionada', text: msg.listResponseMessage.title || msg.listResponseMessage.singleSelectReply?.selectedRowId || 'Resposta de lista', fileName: '', seconds: null };
  if (msg.templateButtonReplyMessage) return { fromMe, id, ts, type: 'button', title: 'Botao selecionado', text: msg.templateButtonReplyMessage.selectedDisplayText || msg.templateButtonReplyMessage.selectedId || 'Resposta de template', fileName: '', seconds: null };
  if (msg.reactionMessage) return { fromMe, id, ts, type: 'reaction', title: 'Reacao', text: `Reacao: ${msg.reactionMessage.text || 'sem texto'}`, fileName: '', seconds: null };
  if (msg.pollCreationMessage || msg.pollCreationMessageV3) { const poll = msg.pollCreationMessage || msg.pollCreationMessageV3; return { fromMe, id, ts, type: 'poll', title: 'Enquete', text: poll.name || 'Enquete recebida', fileName: '', seconds: null }; }
  if (msg.orderMessage) return { fromMe, id, ts, type: 'order', title: 'Pedido', text: 'Pedido recebido', fileName: '', seconds: null };

  return { fromMe, id, ts, type: 'unknown', title: 'Mensagem', text: 'Mensagem sem previa', fileName: '', seconds: null };
}

function getMessageText(raw) {
  return normalizeMessage(raw).text;
}

function normalizeTimestamp(value) {
  if (!value) return Math.floor(Date.now() / 1000);
  if (typeof value === 'number') return value > 9999999999 ? Math.floor(value / 1000) : value;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Math.floor(Date.now() / 1000) : Math.floor(parsed / 1000);
}

function addActivity(db, key, action, by, details = '') {
  const lead = db.leads[key];
  if (!lead) return;
  if (!Array.isArray(lead.activityLog)) lead.activityLog = [];
  lead.activityLog.push({ ts: new Date().toISOString(), action, by, details });
  if (lead.activityLog.length > 100) lead.activityLog = lead.activityLog.slice(-100);
}

function upsertLead(db, lead) {
  const key = leadKey(lead.instance, lead.jid);
  const current = db.leads[key] || {};
  db.leads[key] = {
    id: key,
    jid: lead.jid,
    phone: lead.phone || lead.jid.split('@')[0],
    name: lead.name || current.name || lead.jid.split('@')[0],
    instance: lead.instance,
    lastMsg: lead.lastMsg !== undefined ? lead.lastMsg : (current.lastMsg || ''),
    lastTs: lead.lastTs || current.lastTs || 0,
    profilePic: lead.profilePic !== undefined ? lead.profilePic : (current.profilePic || null),
    status: current.status || 'Novo',
    valor: current.valor || '',
    notes: current.notes || '',
    area: current.area || '',
    source: current.source || '',
    campaign: current.campaign || '',
    followUpAt: current.followUpAt || '',
    tags: Array.isArray(current.tags) ? current.tags : [],
    unread: typeof lead.unread === 'boolean' ? lead.unread : Boolean(current.unread),
    botReplied: typeof lead.botReplied === 'boolean' ? lead.botReplied : Boolean(current.botReplied),
    lastFromMe: typeof lead.lastFromMe === 'boolean' ? lead.lastFromMe : Boolean(current.lastFromMe),
    activityLog: Array.isArray(current.activityLog) ? current.activityLog : [],
    archivedAt: current.archivedAt || null,
    processoNum: current.processoNum || '',
    processoPrazo: current.processoPrazo || '',
    assignedTo: current.assignedTo || '',
    valorPago: current.valorPago || '',
    internalNotes: Array.isArray(current.internalNotes) ? current.internalNotes : [],
    updatedAt: new Date().toISOString(),
    createdAt: current.createdAt || new Date().toISOString(),
  };
  return db.leads[key];
}

function appendMessage(db, instance, jid, rawMessage) {
  const key = leadKey(instance, jid);
  const { fromMe, id, ts, text, type, title, fileName, seconds } = normalizeMessage(rawMessage);

  // Stable deduplication key: prefer the WhatsApp message ID, fall back to content hash
  const msgId = id || `${ts}-${fromMe ? '1' : '0'}-${text.slice(0, 30)}`;

  db.messages[key] = db.messages[key] || [];
  const existing = db.messages[key].find((m) => m.id === msgId);
  if (existing) {
    // Fill in missing fields only — never overwrite fromMe after first storage.
    // findMessages can return wrong fromMe values; the first write (webhook) is authoritative.
    if (!existing.text) existing.text = text;
    if (!existing.type || existing.type === 'unknown') existing.type = type;
    if (!existing.title || existing.title === 'Mensagem') existing.title = title;
    if (!existing.fileName) existing.fileName = fileName || '';
    if (!existing.seconds) existing.seconds = seconds || null;
  } else {
    db.messages[key].push({ id: msgId, text, fromMe, ts, type, title, fileName: fileName || '', seconds: seconds || null });
    db.messages[key] = db.messages[key].sort((a, b) => a.ts - b.ts).slice(-5000);
  }

  return upsertLead(db, {
    instance, jid,
    lastMsg: text,
    lastTs: ts,
    lastFromMe: fromMe,
    botReplied: fromMe || Boolean(db.leads[key]?.botReplied),
    unread: !fromMe,
  });
}

// ─── Evolution API ────────────────────────────────────────────────────────────
function envNameForInstance(instanceName) {
  return `EVOLUTION_API_KEY_${String(instanceName || '')
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').toUpperCase()}`;
}

function getApiKey(instanceName) {
  const envName = instanceName ? envNameForInstance(instanceName) : '';
  return (envName && process.env[envName]) || (instanceName && EVOLUTION_API_KEYS[instanceName]) || EVOLUTION_API_KEY;
}

async function evolution(pathname, options = {}, instanceName = '') {
  const apiKey = getApiKey(instanceName);
  if (!EVOLUTION_API_URL || !apiKey) {
    const hint = instanceName
      ? `Configure ${envNameForInstance(instanceName)} no Railway.`
      : 'Configure EVOLUTION_API_KEY, EVOLUTION_API_KEYS_JSON ou chaves por instancia.';
    const error = new Error(`Configure EVOLUTION_API_URL. ${hint}`);
    error.status = 500;
    throw error;
  }
  const response = await fetch(`${EVOLUTION_API_URL}${pathname}`, {
    ...options,
    headers: { apikey: apiKey, 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const error = new Error(body?.message || `Evolution API respondeu ${response.status}`);
    error.status = response.status;
    error.body = body;
    throw error;
  }
  return body;
}

async function getConfiguredInstances() {
  if (EVOLUTION_API_KEY) {
    const res = await evolution('/instance/fetchInstances');
    return Array.isArray(res) ? res : [];
  }
  const envInstances = Object.keys(process.env)
    .filter((n) => n.startsWith('EVOLUTION_API_KEY_'))
    .map((n) => n.replace('EVOLUTION_API_KEY_', '').replace(/_/g, ' '));
  const names = EVOLUTION_INSTANCES.length
    ? EVOLUTION_INSTANCES
    : [...Object.keys(EVOLUTION_API_KEYS), ...envInstances];
  return names.map((name) => ({ name, connectionStatus: 'open' }));
}

// Parses the varied response formats of /chat/findMessages across Evolution API versions
function parseFindMessagesResponse(response) {
  if (!response) return { records: [], totalPages: 1 };
  // Array directly
  if (Array.isArray(response)) return { records: response, totalPages: 1 };
  // { messages: { records: [...], pages: N } }
  if (Array.isArray(response.messages?.records)) return { records: response.messages.records, totalPages: response.messages.pages || 1 };
  // { records: [...], pages: N }
  if (Array.isArray(response.records)) return { records: response.records, totalPages: response.pages || 1 };
  // { messages: [...] }
  if (Array.isArray(response.messages)) return { records: response.messages, totalPages: 1 };
  // { data: [...] }
  if (Array.isArray(response.data)) return { records: response.data, totalPages: 1 };
  return { records: [], totalPages: 1 };
}

async function syncInstanceLeads(db, instance) {
  const cached = getSyncCache(instance.name);
  if (cached) return cached;

  const chatsResponse = await evolution(
    `/chat/findChats/${encodeURIComponent(instance.name)}`,
    { method: 'POST', body: JSON.stringify({}) },
    instance.name,
  );

  // findChats can return an array or { chats: [...] }
  const chats = Array.isArray(chatsResponse)
    ? chatsResponse
    : (Array.isArray(chatsResponse?.chats) ? chatsResponse.chats : []);

  const leads = [];

  for (const chat of chats) {
    const jid = chat.remoteJid || chat.key?.remoteJid || chat.id || '';
    if (!jid || jid.includes('@g.us') || jid.includes('status@') || jid.includes('broadcast')) continue;

    const lastMessage = chat.lastMessage || {};
    const hasLastMsg = lastMessage && Object.keys(lastMessage).length > 0;

    if (hasLastMsg) appendMessage(db, instance.name, jid, lastMessage);

    const normalized = hasLastMsg ? normalizeMessage(lastMessage) : null;
    const lead = upsertLead(db, {
      jid,
      name: chat.name || chat.pushName || chat.subject || jid.split('@')[0],
      phone: jid.split('@')[0],
      instance: instance.name,
      lastMsg: normalized?.text || chat.lastMessage?.body || '',
      lastTs: normalizeTimestamp(normalized?.ts || lastMessage.messageTimestamp || chat.updatedAt || chat.timestamp),
      profilePic: chat.profilePicUrl || chat.imgUrl || null,
      lastFromMe: normalized?.fromMe ?? false,
      botReplied: normalized?.fromMe ?? false,
    });
    leads.push(lead);
  }

  setSyncCache(instance.name, leads);
  return leads;
}

async function syncFromEvolution(user = null) {
  const allInstances = await getConfiguredInstances();
  const instances = user
    ? allInstances.filter((i) => canAccessInstance(user, i.name))
    : allInstances;

  return withDbLock(async () => {
    const db = await readDb();
    for (const instance of instances) {
      try {
        await syncInstanceLeads(db, instance);
      } catch (e) {
        console.warn(`Nao foi possivel buscar chats da instancia ${instance.name}:`, e.message);
      }
    }
    await writeDb(db);
    const leads = Object.values(db.leads).filter(
      (l) => !l.archivedAt && (!user || canAccessInstance(user, l.instance)),
    );
    return { instances, leads };
  });
}

// ─── Metrics ──────────────────────────────────────────────────────────────────
function buildMetrics(leads) {
  const total = leads.length;
  const byStatus = {};
  const byInstance = {};
  let waitingReply = 0, closed = 0, estimatedRevenue = 0, unread = 0, paidRevenue = 0;

  for (const lead of leads) {
    const status = lead.status || 'Novo';
    byStatus[status] = (byStatus[status] || 0) + 1;
    byInstance[lead.instance] = byInstance[lead.instance] || {
      instance: lead.instance, total: 0, closed: 0, waitingReply: 0, estimatedRevenue: 0, paidRevenue: 0,
    };
    byInstance[lead.instance].total += 1;
    if (!lead.lastFromMe) { waitingReply += 1; byInstance[lead.instance].waitingReply += 1; }
    if (lead.unread) unread += 1;
    if (status === 'Fechado') { closed += 1; byInstance[lead.instance].closed += 1; }
    const value = Number(lead.valor || 0);
    if (!Number.isNaN(value)) {
      estimatedRevenue += value;
      byInstance[lead.instance].estimatedRevenue += value;
    }
    const paid = Number(lead.valorPago || 0);
    if (!Number.isNaN(paid)) {
      paidRevenue += paid;
      byInstance[lead.instance].paidRevenue += paid;
    }
  }

  return {
    total, closed, waitingReply, unread, estimatedRevenue, paidRevenue,
    closeRate: total ? Math.round((closed / total) * 100) : 0,
    byStatus,
    byInstance: Object.values(byInstance).map((i) => ({
      ...i, closeRate: i.total ? Math.round((i.closed / i.total) * 100) : 0,
    })),
  };
}

// ─── Routes: Auth ─────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ message: 'Muitas tentativas. Aguarde 15 minutos.' });
  }
  const { username, password } = req.body || {};
  const users = await getUsers();
  const user = users.find((u) => u.username === username && verifyUserLogin(u, password));
  if (!user) return res.status(401).json({ message: 'Usuario ou senha invalidos' });

  resetRateLimit(ip);
  const publicUser = { username: user.username, name: user.name, role: user.role, instances: user.instances };
  activeSessions.set(user.username, publicUser);
  res.cookie('crm_session', createSession(publicUser), {
    httpOnly: true, sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 12,
  });
  res.json({ user: publicUser });
});

app.post('/api/logout', (req, res) => {
  const user = readSession(req);
  if (user) activeSessions.delete(user.username);
  res.clearCookie('crm_session');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  activeSessions.set(req.user.username, req.user);
  const clients = await getClientSummaries();
  res.json({ user: req.user, clients: req.user.role === 'admin' ? clients : [] });
});

// ─── Routes: SSE ──────────────────────────────────────────────────────────────
app.get('/api/events', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const username = req.user.username;
  activeSessions.set(username, req.user);
  if (!sseClients.has(username)) sseClients.set(username, new Set());
  sseClients.get(username).add(res);
  sseWrite(res, 'connected', { ok: true });

  const ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_) { clearInterval(ping); }
  }, 25000);

  req.on('close', () => {
    clearInterval(ping);
    sseClients.get(username)?.delete(res);
    if (!sseClients.get(username)?.size) sseClients.delete(username);
  });
});

// ─── Routes: Users ────────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, requireAdmin, async (_req, res) => {
  res.json({ users: await getClientSummaries() });
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { name, username, password, instances } = req.body || {};
  const cleanUsername = String(username || '').trim();
  const cleanName = String(name || cleanUsername).trim();
  const cleanInstances = Array.isArray(instances) ? instances.filter(Boolean) : [];
  if (!cleanUsername || !password) return res.status(400).json({ message: 'Usuario e senha sao obrigatorios' });
  const users = await getUsers();
  if (users.some((u) => u.username === cleanUsername)) return res.status(409).json({ message: 'Ja existe usuario com esse login' });
  const db = await readDb();
  const user = {
    id: crypto.randomUUID(), name: cleanName, username: cleanUsername,
    passwordHash: hashPassword(password), instances: cleanInstances,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  };
  db.users.push(user);
  await writeDb(db);
  const clients = await getClientSummaries();
  res.status(201).json({ user: clients.find((u) => u.id === user.id) });
});

app.patch('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const db = await readDb();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'Usuario nao encontrado ou gerenciado por variavel' });
  const { name, username, password, instances } = req.body || {};
  const users = await getUsers();
  if (username && username !== user.username && users.some((u) => u.username === username)) {
    return res.status(409).json({ message: 'Ja existe usuario com esse login' });
  }
  if (name !== undefined) user.name = String(name).trim();
  if (username !== undefined) user.username = String(username).trim();
  if (password) user.passwordHash = hashPassword(password);
  if (Array.isArray(instances)) user.instances = instances.filter(Boolean);
  user.updatedAt = new Date().toISOString();
  await writeDb(db);
  const clients = await getClientSummaries();
  res.json({ user: clients.find((u) => u.id === user.id) });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const db = await readDb();
  const before = db.users.length;
  db.users = db.users.filter((u) => u.id !== req.params.id);
  if (db.users.length === before) return res.status(404).json({ message: 'Usuario nao encontrado ou gerenciado por variavel' });
  await writeDb(db);
  res.json({ ok: true });
});

// ─── Routes: Templates ────────────────────────────────────────────────────────
app.get('/api/templates', requireAuth, async (_req, res) => {
  const db = await readDb();
  res.json({ templates: db.templates || [] });
});

app.post('/api/templates', requireAuth, requireAdmin, async (req, res) => {
  const { label, text } = req.body || {};
  if (!label || !text) return res.status(400).json({ message: 'Label e texto sao obrigatorios' });
  const db = await readDb();
  const template = {
    id: crypto.randomUUID(), label: String(label).trim(), text: String(text).trim(),
    createdAt: new Date().toISOString(),
  };
  db.templates.push(template);
  await writeDb(db);
  res.status(201).json({ template });
});

app.patch('/api/templates/:id', requireAuth, requireAdmin, async (req, res) => {
  const db = await readDb();
  const template = db.templates.find((t) => t.id === req.params.id);
  if (!template) return res.status(404).json({ message: 'Template nao encontrado' });
  if (req.body.label !== undefined) template.label = String(req.body.label).trim();
  if (req.body.text !== undefined) template.text = String(req.body.text).trim();
  template.updatedAt = new Date().toISOString();
  await writeDb(db);
  res.json({ template });
});

app.delete('/api/templates/:id', requireAuth, requireAdmin, async (req, res) => {
  const db = await readDb();
  const before = db.templates.length;
  db.templates = db.templates.filter((t) => t.id !== req.params.id);
  if (db.templates.length === before) return res.status(404).json({ message: 'Template nao encontrado' });
  await writeDb(db);
  res.json({ ok: true });
});

// ─── Routes: Instances ────────────────────────────────────────────────────────
app.get('/api/instances', requireAuth, async (req, res) => {
  try {
    const instances = await getConfiguredInstances();
    res.json(instances.filter((i) => canAccessInstance(req.user, i.name)));
  } catch (e) {
    res.status(e.status || 500).json({ message: e.message, details: e.body || null });
  }
});

// ─── Routes: Reset messages (limpa mensagens corrompidas de um lead) ──────────
app.delete('/api/leads/:id/messages/reset', requireAuth, requireAdmin, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });
  await withDbLock(async () => {
    const db = await readDb();
    if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
    db.messages[id] = [];
    clearSyncCache(instance);
    await writeDb(db);
    res.json({ ok: true });
  });
});

// ─── Routes: Health ───────────────────────────────────────────────────────────
app.get('/api/health', requireAuth, async (req, res) => {
  try {
    clearSyncCache();
    const data = await syncFromEvolution(req.user);
    res.json({ ok: true, instances: data.instances.length, leads: data.leads.length });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, message: e.message });
  }
});

// ─── Routes: Leads ────────────────────────────────────────────────────────────
app.get('/api/leads', requireAuth, async (req, res) => {
  try {
    const { instances, leads } = await syncFromEvolution(req.user);

    const {
      search = '', status = '', area = '', instance: instFilter = '',
      sort = 'recent', page = '1', limit = '100',
    } = req.query;

    let filtered = leads;

    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter((l) =>
        [l.name, l.phone, l.lastMsg, l.area, l.source, l.campaign, l.notes, l.instance]
          .some((v) => String(v || '').toLowerCase().includes(q)),
      );
    }
    if (status) filtered = filtered.filter((l) => (l.status || 'Novo') === status);
    if (area) filtered = filtered.filter((l) => l.area === area);
    if (instFilter) filtered = filtered.filter((l) => l.instance === instFilter);

    const sortFns = {
      recent: (a, b) => (b.lastTs || 0) - (a.lastTs || 0),
      oldest: (a, b) => (a.lastTs || 0) - (b.lastTs || 0),
      followup: (a, b) => {
        const aT = a.followUpAt ? new Date(a.followUpAt).getTime() : Number.MAX_SAFE_INTEGER;
        const bT = b.followUpAt ? new Date(b.followUpAt).getTime() : Number.MAX_SAFE_INTEGER;
        return aT - bT;
      },
      value: (a, b) => (Number(b.valor || 0) || 0) - (Number(a.valor || 0) || 0),
      unread: (a, b) => (b.unread ? 1 : 0) - (a.unread ? 1 : 0) || (b.lastTs || 0) - (a.lastTs || 0),
    };
    filtered.sort(sortFns[sort] || sortFns.recent);

    const pageNum = Math.max(1, Number(page));
    const limitNum = Math.min(200, Math.max(1, Number(limit)));
    const totalFiltered = filtered.length;
    const paginated = filtered.slice((pageNum - 1) * limitNum, pageNum * limitNum);

    res.json({
      instances,
      leads: paginated,
      metrics: buildMetrics(leads),
      total: totalFiltered,
      page: pageNum,
      limit: limitNum,
      pages: Math.ceil(totalFiltered / limitNum),
    });
  } catch (e) {
    res.status(e.status || 500).json({ message: e.message, details: e.body || null });
  }
});

app.post('/api/leads', requireAuth, async (req, res) => {
  const { instance, phone, name } = req.body || {};
  if (!instance || !phone) return res.status(400).json({ message: 'Instancia e telefone sao obrigatorios' });
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso a esta instancia' });

  const cleanPhone = String(phone).replace(/\D/g, '');
  if (cleanPhone.length < 10) return res.status(400).json({ message: 'Telefone invalido' });

  const jid = `${cleanPhone}@s.whatsapp.net`;

  await withDbLock(async () => {
    const db = await readDb();
    const lead = upsertLead(db, { instance, jid, phone: cleanPhone, name: name || cleanPhone });
    addActivity(db, lead.id, 'criado', req.user.username, 'Lead criado manualmente');
    await writeDb(db);
    clearSyncCache(instance);
    res.status(201).json(lead);
  });
});

app.patch('/api/leads/:id', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso a este cliente' });

  await withDbLock(async () => {
    const db = await readDb();
    if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });

    const allowed = ['status', 'valor', 'valorPago', 'notes', 'area', 'source', 'campaign', 'followUpAt', 'name', 'tags', 'processoNum', 'processoPrazo', 'assignedTo'];
    const changes = [];
    for (const field of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, field)) {
        const oldVal = db.leads[id][field];
        db.leads[id][field] = field === 'tags'
          ? (Array.isArray(req.body[field]) ? req.body[field] : [])
          : (req.body[field] ?? '');
        if (field === 'status' && oldVal !== db.leads[id][field]) {
          changes.push(`status: ${oldVal} → ${db.leads[id][field]}`);
        }
      }
    }
    if (req.body.unread === false) db.leads[id].unread = false;
    db.leads[id].updatedAt = new Date().toISOString();
    if (changes.length) addActivity(db, id, 'atualizado', req.user.username, changes.join(', '));
    await writeDb(db);
    res.json(db.leads[id]);
  });
});

app.delete('/api/leads/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });

  await withDbLock(async () => {
    const db = await readDb();
    if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
    db.leads[id].archivedAt = new Date().toISOString();
    await writeDb(db);
    clearSyncCache(instance);
    res.json({ ok: true });
  });
});

app.get('/api/leads/:id/activity', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });
  const db = await readDb();
  if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
  res.json({ activity: [...(db.leads[id].activityLog || [])].reverse() });
});

// ─── Routes: Messages ─────────────────────────────────────────────────────────
app.get('/api/leads/:id/messages', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance, jid } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso a esta conversa' });

  const offset = Math.min(Math.max(Number(req.query.offset) || 80, 1), 200);
  const maxPages = Math.min(Math.max(Number(req.query.pages) || 5, 1), 10);

  // ── Step 1: fetch from Evolution API OUTSIDE the lock (network call) ──
  const fetchedRecords = [];
  try {
    for (let page = 1; page <= maxPages; page++) {
      const response = await evolution(
        `/chat/findMessages/${encodeURIComponent(instance)}`,
        { method: 'POST', body: JSON.stringify({ where: { key: { remoteJid: jid } }, offset, page }) },
        instance,
      );
      const { records, totalPages } = parseFindMessagesResponse(response);
      for (const msg of records) fetchedRecords.push(msg);
      if (!records.length || page >= totalPages) break;
    }
  } catch (e) {
    console.warn(`Nao foi possivel buscar mensagens de ${id}:`, e.message);
  }

  // ── Step 2: persist inside lock (DB only, no network) ──
  await withDbLock(async () => {
    const db = await readDb();

    for (const msg of fetchedRecords) {
      appendMessage(db, instance, jid, msg);
    }

    if (db.leads[id]) {
      db.leads[id].unread = false;
      const lead = db.leads[id];
      // If no messages arrived from Evolution, seed from last known message
      if (lead.lastMsg && !(db.messages[id] || []).length) {
        appendMessage(db, instance, jid, {
          id: `seed-${lead.lastTs || Date.now()}`,
          key: { fromMe: lead.lastFromMe ?? false },
          message: { conversation: lead.lastMsg },
          messageTimestamp: lead.lastTs || Math.floor(Date.now() / 1000),
        });
      }
    }
    await writeDb(db);
    res.json((db.messages[id] || []).sort((a, b) => a.ts - b.ts));
  });
});

app.post('/api/leads/:id/messages/send', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance, jid } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso a esta conversa' });

  const text = String(req.body?.text || '').trim();
  if (!text) return res.status(400).json({ message: 'Digite uma mensagem' });

  const db = await readDb();
  if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });

  const number = jidToNumber(jid);
  const rawJid = String(jid || '');
  const isDirectChat = /^\d+$/.test(rawJid) || rawJid.includes('@s.whatsapp.net') || rawJid.includes('@c.us');
  if (!number || !isDirectChat) {
    return res.status(400).json({ message: 'Esta conversa nao possui numero valido para resposta direta.' });
  }

  try {
    const response = await evolution(
      `/message/sendText/${encodeURIComponent(instance)}`,
      { method: 'POST', body: JSON.stringify({ number, text }) },
      instance,
    );

    await withDbLock(async () => {
      const db2 = await readDb();
      appendMessage(db2, instance, jid, {
        id: response?.key?.id || response?.messageId || `crm-${Date.now()}`,
        message: { conversation: text },
        messageTimestamp: Math.floor(Date.now() / 1000),
        key: { fromMe: true },
      });
      addActivity(db2, id, 'mensagem_enviada', req.user.username, text.slice(0, 80));
      await writeDb(db2);
      sseNotifyForInstance(instance, 'lead_updated', {
        id, lastMsg: text, lastFromMe: true, lastTs: Math.floor(Date.now() / 1000),
      });
    });

    const db3 = await readDb();
    res.status(201).json({ ok: true, messages: (db3.messages[id] || []).sort((a, b) => a.ts - b.ts) });
  } catch (e) {
    res.status(e.status || 500).json({ message: e.message, details: e.body || null });
  }
});

// ─── Routes: Internal Notes ───────────────────────────────────────────────────
app.get('/api/leads/:id/notes', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });
  const db = await readDb();
  if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
  res.json({ notes: db.leads[id].internalNotes || [] });
});

app.post('/api/leads/:id/notes', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });
  const text = String(req.body?.text || '').trim();
  if (!text) return res.status(400).json({ message: 'Texto da nota obrigatorio' });

  await withDbLock(async () => {
    const db = await readDb();
    if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
    if (!Array.isArray(db.leads[id].internalNotes)) db.leads[id].internalNotes = [];
    const note = {
      id: crypto.randomUUID(),
      text,
      by: req.user.username,
      byName: req.user.name || req.user.username,
      createdAt: new Date().toISOString(),
    };
    db.leads[id].internalNotes.push(note);
    addActivity(db, id, 'nota_adicionada', req.user.username, text.slice(0, 80));
    await writeDb(db);
    res.status(201).json({ note });
  });
});

app.delete('/api/leads/:id/notes/:noteId', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { noteId } = req.params;
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });

  await withDbLock(async () => {
    const db = await readDb();
    if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
    const notes = db.leads[id].internalNotes || [];
    const note = notes.find((n) => n.id === noteId);
    if (!note) return res.status(404).json({ message: 'Nota nao encontrada' });
    if (note.by !== req.user.username && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Apenas o autor ou admin pode excluir' });
    }
    db.leads[id].internalNotes = notes.filter((n) => n.id !== noteId);
    await writeDb(db);
    res.json({ ok: true });
  });
});

// ─── Routes: LGPD ─────────────────────────────────────────────────────────────
app.get('/api/leads/:id/export', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });
  const db = await readDb();
  if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
  const exportData = {
    lead: db.leads[id],
    messages: db.messages[id] || [],
    exportedAt: new Date().toISOString(),
    exportedBy: req.user.username,
  };
  const safeName = String(id).replace(/[^a-zA-Z0-9]/g, '-').slice(0, 60);
  res.setHeader('Content-Disposition', `attachment; filename="dados-${safeName}.json"`);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.send(JSON.stringify(exportData, null, 2));
});

app.delete('/api/leads/:id/permanent', requireAuth, requireAdmin, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });

  await withDbLock(async () => {
    const db = await readDb();
    if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });
    delete db.leads[id];
    delete db.messages[id];
    await writeDb(db);
    clearSyncCache(instance);
    res.json({ ok: true });
  });
});

// ─── Routes: Lembrete e NPS ───────────────────────────────────────────────────
app.post('/api/leads/:id/reminder', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance, jid } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });

  const text = String(req.body?.text || '').trim();
  if (!text) return res.status(400).json({ message: 'Texto do lembrete obrigatorio' });

  const number = jidToNumber(jid);
  if (!number) return res.status(400).json({ message: 'Numero invalido para envio' });

  try {
    const response = await evolution(
      `/message/sendText/${encodeURIComponent(instance)}`,
      { method: 'POST', body: JSON.stringify({ number, text }) },
      instance,
    );
    await withDbLock(async () => {
      const db2 = await readDb();
      appendMessage(db2, instance, jid, {
        id: response?.key?.id || `reminder-${Date.now()}`,
        message: { conversation: text },
        messageTimestamp: Math.floor(Date.now() / 1000),
        key: { fromMe: true },
      });
      addActivity(db2, id, 'lembrete_enviado', req.user.username, text.slice(0, 80));
      await writeDb(db2);
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ message: e.message, details: e.body || null });
  }
});

app.post('/api/leads/:id/nps', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance, jid } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso' });

  const number = jidToNumber(jid);
  if (!number) return res.status(400).json({ message: 'Numero invalido para envio' });

  const npsText = String(req.body?.text || '').trim() ||
    'Ola! De 0 a 10, o quanto voce indicaria nosso escritorio para amigos e familiares? Responda apenas com o numero. Sua opiniao e muito importante para nos! 🙏';

  try {
    await evolution(
      `/message/sendText/${encodeURIComponent(instance)}`,
      { method: 'POST', body: JSON.stringify({ number, text: npsText }) },
      instance,
    );
    await withDbLock(async () => {
      const db2 = await readDb();
      addActivity(db2, id, 'nps_enviado', req.user.username, 'Pesquisa NPS enviada');
      await writeDb(db2);
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ message: e.message, details: e.body || null });
  }
});

// ─── Routes: Analytics ────────────────────────────────────────────────────────
app.get('/api/analytics/campaigns', requireAuth, async (req, res) => {
  const db = await readDb();
  const campaignMap = {};

  for (const lead of Object.values(db.leads)) {
    if (lead.archivedAt) continue;
    if (!canAccessInstance(req.user, lead.instance)) continue;
    const campaign = lead.campaign || 'Sem campanha';
    if (!campaignMap[campaign]) {
      campaignMap[campaign] = { campaign, total: 0, closed: 0, lost: 0, estimatedRevenue: 0, paidRevenue: 0 };
    }
    campaignMap[campaign].total++;
    if (lead.status === 'Fechado') {
      campaignMap[campaign].closed++;
      const v = Number(lead.valor || 0);
      if (!Number.isNaN(v)) campaignMap[campaign].estimatedRevenue += v;
    }
    if (lead.status === 'Perdido') campaignMap[campaign].lost++;
    const p = Number(lead.valorPago || 0);
    if (!Number.isNaN(p)) campaignMap[campaign].paidRevenue += p;
  }

  const campaigns = Object.values(campaignMap)
    .map((c) => ({ ...c, closeRate: c.total ? Math.round((c.closed / c.total) * 100) : 0 }))
    .sort((a, b) => b.total - a.total);

  res.json({ campaigns });
});

// ─── Routes: Webhook ──────────────────────────────────────────────────────────
app.post('/webhook/evolution', async (req, res) => {
  if (WEBHOOK_SECRET) {
    const token = req.get('x-webhook-secret') || req.query.secret;
    if (token !== WEBHOOK_SECRET) return res.status(401).json({ message: 'Webhook nao autorizado' });
  }

  const payload = req.body || {};
  const instance = payload.instance || payload.instanceName || payload.data?.instance || payload.sender || 'default';

  // Validate instance is among configured ones (only when using per-instance keys)
  if (!EVOLUTION_API_KEY && EVOLUTION_INSTANCES.length) {
    const normalizedIncoming = envNameForInstance(instance);
    const isKnown = EVOLUTION_INSTANCES.some(
      (n) => n === instance || envNameForInstance(n) === normalizedIncoming,
    );
    if (!isKnown) return res.status(403).json({ message: 'Instancia nao configurada' });
  }

  const records = Array.isArray(payload.data) ? payload.data : [payload.data || payload];
  let saved = 0;

  await withDbLock(async () => {
    const db = await readDb();
    const updated = [];
    for (const record of records) {
      const jid = record.key?.remoteJid || record.remoteJid || record.from || record.chatId;
      if (!jid || jid.includes('@g.us') || jid.includes('status@')) continue;
      const lead = appendMessage(db, instance, jid, record);
      updated.push(lead);
      saved++;
    }
    await writeDb(db);
    clearSyncCache(instance);
    for (const lead of updated) {
      sseNotifyForInstance(instance, 'new_message', {
        leadId: lead.id,
        instance: lead.instance,
        name: lead.name,
        phone: lead.phone,
        lastMsg: lead.lastMsg,
        lastTs: lead.lastTs,
        unread: lead.unread,
      });
    }
  });

  res.json({ ok: true, saved });
});

// ─── Static ───────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Startup ──────────────────────────────────────────────────────────────────
ensureDb()
  .then(() => {
    app.listen(PORT, () => console.log(`CRM rodando na porta ${PORT}`));
  })
  .catch((err) => {
    console.error('Falha ao inicializar banco de dados:', err);
    process.exit(1);
  });
