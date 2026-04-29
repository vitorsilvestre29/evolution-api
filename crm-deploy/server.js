const express = require('express');
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

function envNameForInstance(instanceName) {
  return `EVOLUTION_API_KEY_${String(instanceName || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase()}`;
}

app.use(express.json({ limit: '5mb' }));

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ leads: {}, messages: {} }, null, 2));
  }
}

function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
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
    db.messages[key] = db.messages[key].sort((a, b) => a.ts - b.ts).slice(-80);
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

async function syncFromEvolution() {
  const db = readDb();
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
  return { instances, leads: Object.values(db.leads) };
}

app.get('/api/health', async (_req, res) => {
  try {
    const data = await syncFromEvolution();
    res.json({ ok: true, instances: data.instances.length, leads: data.leads.length });
  } catch (error) {
    res.status(error.status || 500).json({ ok: false, message: error.message });
  }
});

app.get('/api/instances', async (_req, res) => {
  try {
    if (EVOLUTION_API_KEY) {
      const instances = await evolution('/instance/fetchInstances');
      res.json(Array.isArray(instances) ? instances : []);
      return;
    }

    const envInstances = Object.keys(process.env)
      .filter((name) => name.startsWith('EVOLUTION_API_KEY_'))
      .map((name) => name.replace('EVOLUTION_API_KEY_', '').replace(/_/g, ' '));
    const names = EVOLUTION_INSTANCES.length ? EVOLUTION_INSTANCES : [...Object.keys(EVOLUTION_API_KEYS), ...envInstances];
    res.json(names.map((name) => ({ name, connectionStatus: 'open' })));
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message, details: error.body || null });
  }
});

app.get('/api/leads', async (_req, res) => {
  try {
    const { instances, leads } = await syncFromEvolution();
    res.json({ instances, leads: leads.sort((a, b) => b.lastTs - a.lastTs) });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message, details: error.body || null });
  }
});

app.patch('/api/leads/:id', (req, res) => {
  const id = decodeURIComponent(req.params.id);
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

app.get('/api/leads/:id/messages', async (req, res) => {
  const id = decodeURIComponent(req.params.id);
  const { instance, jid } = splitLeadKey(id);
  const db = readDb();
  const offset = Math.min(Math.max(Number(req.query.offset) || 80, 1), 200);
  const page = Math.max(Number(req.query.page) || 1, 1);

  try {
    const response = await evolution(`/chat/findMessages/${encodeURIComponent(instance)}`, {
      method: 'POST',
      body: JSON.stringify({ where: { key: { remoteJid: jid } }, offset, page }),
    }, instance);
    const records = response?.messages?.records || response?.records || response?.messages || [];
    for (const message of records) appendMessage(db, instance, jid, message);
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
