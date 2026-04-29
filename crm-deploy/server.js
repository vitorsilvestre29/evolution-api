const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const EVOLUTION_API_URL = (process.env.EVOLUTION_API_URL || '').replace(/\/$/, '');
const EVOLUTION_API_KEY = process.env.EVOLUTION_API_KEY || '';
const EVOLUTION_INSTANCES = (process.env.EVOLUTION_INSTANCES || '')
  .split(',')
  .map((name) => name.trim())
  .filter(Boolean);
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const SESSION_SECRET = process.env.CRM_SESSION_SECRET || WEBHOOK_SECRET || 'change-me';
const ADMIN_USER = process.env.CRM_ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.CRM_ADMIN_PASSWORD || '';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'crm.json');

let EVOLUTION_API_KEYS = {};
try {
  EVOLUTION_API_KEYS = process.env.EVOLUTION_API_KEYS_JSON
    ? JSON.parse(process.env.EVOLUTION_API_KEYS_JSON)
    : {};
} catch (_error) {
  EVOLUTION_API_KEYS = {};
}

let CRM_CLIENTS = [];
try {
  CRM_CLIENTS = process.env.CRM_CLIENTS_JSON ? JSON.parse(process.env.CRM_CLIENTS_JSON) : [];
} catch (_error) {
  CRM_CLIENTS = [];
}

function envNameForInstance(instanceName) {
  return `EVOLUTION_API_KEY_${String(instanceName || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase()}`;
}

app.use(express.json({ limit: '5mb' }));

function parseCookies(header = '') {
  return Object.fromEntries(
    header
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf('=');
        return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
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
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(testHash, 'hex'));
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
  } catch (_error) {
    return null;
  }
}

function getUsers() {
  const db = readDb();
  const clients = Array.isArray(CRM_CLIENTS) ? CRM_CLIENTS : [];
  const users = clients.map((client) => ({
    id: client.username,
    username: client.username,
    password: client.password,
    name: client.name || client.username,
    role: 'client',
    instances: Array.isArray(client.instances) ? client.instances : [],
    source: 'env',
  }));

  for (const user of db.users || []) {
    users.push({
      id: user.id,
      username: user.username,
      passwordHash: user.passwordHash,
      name: user.name || user.username,
      role: 'client',
      instances: Array.isArray(user.instances) ? user.instances : [],
      source: 'db',
    });
  }

  if (ADMIN_PASSWORD) {
    users.push({
      id: 'admin',
      username: ADMIN_USER,
      password: ADMIN_PASSWORD,
      name: 'Administrador',
      role: 'admin',
      instances: [],
      source: 'env',
    });
  }

  return users;
}

function verifyUserLogin(user, password) {
  if (user.passwordHash) return verifyPassword(password, user.passwordHash);
  return user.password === password;
}

function getClientSummaries() {
  return getUsers()
    .filter((user) => user.role === 'client')
    .map((user) => ({
      id: user.id,
      name: user.name,
      username: user.username,
      instances: user.instances,
      source: user.source,
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

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ leads: {}, messages: {}, users: [] }, null, 2));
  }
}

function readDb() {
  ensureDb();
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  db.leads = db.leads || {};
  db.messages = db.messages || {};
  db.users = Array.isArray(db.users) ? db.users : [];
  return db;
}

function writeDb(db) {
  ensureDb();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function leadKey(instance, jid) {
  return `${instance}::${jid}`;
}

function splitLeadKey(key) {
  const [instance, ...jidParts] = key.split('::');
  return { instance, jid: jidParts.join('::') };
}

function getMessageText(message = {}) {
  return (
    message.conversation ||
    message.extendedTextMessage?.text ||
    message.imageMessage?.caption ||
    message.videoMessage?.caption ||
    message.buttonsResponseMessage?.selectedDisplayText ||
    message.listResponseMessage?.title ||
    message.templateButtonReplyMessage?.selectedDisplayText ||
    message.reactionMessage?.text ||
    message.documentMessage?.caption ||
    (message.audioMessage ? 'Audio' : '') ||
    (message.imageMessage ? 'Imagem' : '') ||
    (message.videoMessage ? 'Video' : '') ||
    (message.documentMessage ? 'Documento' : '') ||
    (message.stickerMessage ? 'Figurinha' : '') ||
    'Mensagem'
  );
}

function normalizeTimestamp(value) {
  if (!value) return Math.floor(Date.now() / 1000);
  if (typeof value === 'number') return value > 9999999999 ? Math.floor(value / 1000) : value;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Math.floor(Date.now() / 1000) : Math.floor(parsed / 1000);
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
    lastMsg: lead.lastMsg || current.lastMsg || '',
    lastTs: lead.lastTs || current.lastTs || 0,
    profilePic: lead.profilePic || current.profilePic || null,
    status: current.status || 'Novo',
    valor: current.valor || '',
    notes: current.notes || '',
    botReplied: typeof lead.botReplied === 'boolean' ? lead.botReplied : Boolean(current.botReplied),
    lastFromMe: typeof lead.lastFromMe === 'boolean' ? lead.lastFromMe : Boolean(current.lastFromMe),
    updatedAt: new Date().toISOString(),
    createdAt: current.createdAt || new Date().toISOString(),
  };
  return db.leads[key];
}

function appendMessage(db, instance, jid, rawMessage) {
  const key = leadKey(instance, jid);
  const message = rawMessage.message || rawMessage;
  const text = getMessageText(message);
  const fromMe = rawMessage.key?.fromMe === true || rawMessage.key?.fromMe === 'true' || rawMessage.fromMe === true;
  const ts = normalizeTimestamp(rawMessage.messageTimestamp || rawMessage.timestamp || rawMessage.createdAt);
  const msgId = rawMessage.key?.id || rawMessage.id || `${ts}-${fromMe}-${text.slice(0, 20)}`;

  db.messages[key] = db.messages[key] || [];
  if (!db.messages[key].some((item) => item.id === msgId)) {
    db.messages[key].push({ id: msgId, text, fromMe, ts });
    db.messages[key] = db.messages[key].sort((a, b) => a.ts - b.ts).slice(-5000);
  }

  return upsertLead(db, {
    instance,
    jid,
    lastMsg: text,
    lastTs: ts,
    lastFromMe: fromMe,
    botReplied: fromMe || db.leads[key]?.botReplied,
  });
}

function getApiKey(instanceName) {
  const instanceEnvName = instanceName ? envNameForInstance(instanceName) : '';
  return (
    (instanceEnvName && process.env[instanceEnvName]) ||
    (instanceName && EVOLUTION_API_KEYS[instanceName]) ||
    EVOLUTION_API_KEY
  );
}

async function evolution(pathname, options = {}, instanceName = '') {
  const apiKey = getApiKey(instanceName);
  if (!EVOLUTION_API_URL || !apiKey) {
    const keyHint = instanceName
      ? `Configure ${envNameForInstance(instanceName)} no Railway.`
      : 'Configure EVOLUTION_API_KEY, EVOLUTION_API_KEYS_JSON ou as chaves por instancia no Railway.';
    const error = new Error(`Configure EVOLUTION_API_URL. ${keyHint}`);
    error.status = 500;
    throw error;
  }

  const response = await fetch(`${EVOLUTION_API_URL}${pathname}`, {
    ...options,
    headers: {
      apikey: apiKey,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
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
  let instances = [];

  if (EVOLUTION_API_KEY) {
    const instancesResponse = await evolution('/instance/fetchInstances');
    instances = Array.isArray(instancesResponse) ? instancesResponse : [];
  } else {
    const envInstances = Object.keys(process.env)
      .filter((name) => name.startsWith('EVOLUTION_API_KEY_'))
      .map((name) => name.replace('EVOLUTION_API_KEY_', '').replace(/_/g, ' '));
    const names = EVOLUTION_INSTANCES.length ? EVOLUTION_INSTANCES : [...Object.keys(EVOLUTION_API_KEYS), ...envInstances];
    instances = names.map((name) => ({ name, connectionStatus: 'open' }));
  }

  return instances;
}

async function syncFromEvolution(user = null) {
  const db = readDb();
  const allInstances = await getConfiguredInstances();
  const instances = user
    ? allInstances.filter((instance) => canAccessInstance(user, instance.name))
    : allInstances;

  for (const instance of instances) {
    try {
      const chatsResponse = await evolution(`/chat/findChats/${encodeURIComponent(instance.name)}`, {
        method: 'POST',
        body: JSON.stringify({}),
      }, instance.name);
      const chats = Array.isArray(chatsResponse) ? chatsResponse : chatsResponse?.chats || [];

      for (const chat of chats) {
        const jid = chat.remoteJid || chat.key?.remoteJid || chat.id || '';
        if (!jid || jid.includes('@g.us') || jid.includes('status@')) continue;

        const lastMessage = chat.lastMessage || {};
        const message = lastMessage.message || lastMessage;
        if (lastMessage && Object.keys(lastMessage).length) {
          appendMessage(db, instance.name, jid, lastMessage);
        }
        upsertLead(db, {
          jid,
          name: chat.name || chat.pushName || jid.split('@')[0],
          phone: jid.split('@')[0],
          instance: instance.name,
          lastMsg: getMessageText(message),
          lastTs: normalizeTimestamp(lastMessage.messageTimestamp || chat.updatedAt),
          profilePic: chat.profilePicUrl || null,
          lastFromMe: lastMessage.key?.fromMe === true || lastMessage.key?.fromMe === 'true',
          botReplied: lastMessage.key?.fromMe === true || lastMessage.key?.fromMe === 'true',
        });
      }
    } catch (error) {
      console.warn(`Nao foi possivel buscar chats da instancia ${instance.name}:`, error.message);
    }
  }

  writeDb(db);
  const allowedLeads = Object.values(db.leads).filter((lead) => !user || canAccessInstance(user, lead.instance));
  return { instances, leads: allowedLeads };
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = getUsers().find((item) => item.username === username && verifyUserLogin(item, password));
  if (!user) return res.status(401).json({ message: 'Usuario ou senha invalidos' });

  const publicUser = {
    username: user.username,
    name: user.name,
    role: user.role,
    instances: user.instances,
  };
  res.cookie('crm_session', createSession(publicUser), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 12,
  });
  res.json({ user: publicUser });
});

app.post('/api/logout', (_req, res) => {
  res.clearCookie('crm_session');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const clients = getClientSummaries();
  res.json({ user: req.user, clients: req.user.role === 'admin' ? clients : [] });
});

app.get('/api/users', requireAuth, requireAdmin, (_req, res) => {
  res.json({ users: getClientSummaries() });
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { name, username, password, instances } = req.body || {};
  const cleanUsername = String(username || '').trim();
  const cleanName = String(name || cleanUsername).trim();
  const cleanInstances = Array.isArray(instances) ? instances.filter(Boolean) : [];

  if (!cleanUsername || !password) return res.status(400).json({ message: 'Usuario e senha sao obrigatorios' });
  if (getUsers().some((user) => user.username === cleanUsername)) {
    return res.status(409).json({ message: 'Ja existe usuario com esse login' });
  }

  const db = readDb();
  const user = {
    id: crypto.randomUUID(),
    name: cleanName,
    username: cleanUsername,
    passwordHash: hashPassword(password),
    instances: cleanInstances,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.users.push(user);
  writeDb(db);
  res.status(201).json({ user: getClientSummaries().find((item) => item.id === user.id) });
});

app.patch('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'Usuario nao encontrado ou gerenciado por variable' });

  const { name, username, password, instances } = req.body || {};
  if (username && username !== user.username && getUsers().some((item) => item.username === username)) {
    return res.status(409).json({ message: 'Ja existe usuario com esse login' });
  }

  if (name !== undefined) user.name = String(name).trim();
  if (username !== undefined) user.username = String(username).trim();
  if (password) user.passwordHash = hashPassword(password);
  if (Array.isArray(instances)) user.instances = instances.filter(Boolean);
  user.updatedAt = new Date().toISOString();
  writeDb(db);
  res.json({ user: getClientSummaries().find((item) => item.id === user.id) });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const db = readDb();
  const before = db.users.length;
  db.users = db.users.filter((item) => item.id !== req.params.id);
  if (db.users.length === before) return res.status(404).json({ message: 'Usuario nao encontrado ou gerenciado por variable' });
  writeDb(db);
  res.json({ ok: true });
});

app.get('/api/health', requireAuth, async (req, res) => {
  try {
    const data = await syncFromEvolution(req.user);
    res.json({ ok: true, instances: data.instances.length, leads: data.leads.length });
  } catch (error) {
    res.status(error.status || 500).json({ ok: false, message: error.message });
  }
});

app.get('/api/instances', requireAuth, async (req, res) => {
  try {
    const instances = await getConfiguredInstances();
    res.json(instances.filter((instance) => canAccessInstance(req.user, instance.name)));
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message, details: error.body || null });
  }
});

app.get('/api/leads', requireAuth, async (req, res) => {
  try {
    const { instances, leads } = await syncFromEvolution(req.user);
    res.json({ instances, leads: leads.sort((a, b) => b.lastTs - a.lastTs) });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message, details: error.body || null });
  }
});

app.patch('/api/leads/:id', requireAuth, (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso a este cliente' });

  const db = readDb();
  if (!db.leads[id]) return res.status(404).json({ message: 'Lead nao encontrado' });

  const allowed = ['status', 'valor', 'notes'];
  for (const field of allowed) {
    if (Object.prototype.hasOwnProperty.call(req.body, field)) db.leads[id][field] = req.body[field] || '';
  }
  db.leads[id].updatedAt = new Date().toISOString();
  writeDb(db);
  res.json(db.leads[id]);
});

app.get('/api/leads/:id/messages', requireAuth, async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance, jid } = splitLeadKey(id);
  if (!canAccessInstance(req.user, instance)) return res.status(403).json({ message: 'Sem acesso a esta conversa' });

  const db = readDb();
  const offset = Math.min(Math.max(Number(req.query.offset) || 80, 1), 200);
  const pages = Math.min(Math.max(Number(req.query.pages) || 5, 1), 10);

  try {
    for (let page = 1; page <= pages; page += 1) {
      const response = await evolution(`/chat/findMessages/${encodeURIComponent(instance)}`, {
        method: 'POST',
        body: JSON.stringify({ where: { key: { remoteJid: jid } }, offset, page }),
      }, instance);
      const records = response?.messages?.records || response?.records || response?.messages || [];
      if (!records.length) break;
      for (const message of records) appendMessage(db, instance, jid, message);
      const totalPages = response?.messages?.pages || response?.pages || pages;
      if (page >= totalPages) break;
    }
    writeDb(db);
  } catch (error) {
    console.warn(`Nao foi possivel buscar mensagens de ${id}:`, error.message);
  }

  const lead = db.leads[id];
  if (lead?.lastMsg && !(db.messages[id] || []).length) {
    appendMessage(db, instance, jid, {
      id: `lead-last-${lead.lastTs || Date.now()}`,
      message: { conversation: lead.lastMsg },
      messageTimestamp: lead.lastTs,
      key: { fromMe: lead.lastFromMe },
    });
    writeDb(db);
  }

  res.json((db.messages[id] || []).sort((a, b) => a.ts - b.ts));
});

app.post('/webhook/evolution', (req, res) => {
  if (WEBHOOK_SECRET) {
    const token = req.get('x-webhook-secret') || req.query.secret;
    if (token !== WEBHOOK_SECRET) return res.status(401).json({ message: 'Webhook nao autorizado' });
  }

  const payload = req.body || {};
  const instance = payload.instance || payload.instanceName || payload.data?.instance || payload.sender || 'default';
  const records = Array.isArray(payload.data) ? payload.data : [payload.data || payload];
  const db = readDb();
  let saved = 0;

  for (const record of records) {
    const jid = record.key?.remoteJid || record.remoteJid || record.from || record.chatId;
    if (!jid || jid.includes('@g.us') || jid.includes('status@')) continue;
    appendMessage(db, instance, jid, record);
    saved += 1;
  }

  writeDb(db);
  res.json({ ok: true, saved });
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CRM rodando na porta ${PORT}`);
});
