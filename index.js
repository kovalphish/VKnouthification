import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';

const PORT = Number(process.env.PORT) || 3000;
const VK_API_VERSION = '5.199';
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 час
const MAX_BRIDGES = 50;

const startedAt = Date.now();
let totalSentAll = 0;

// Активные подключения: sessionId -> BridgeInstance
const bridges = new Map();

// ---------------- Вспомогательные функции ----------------

function extractBarkKey(raw) {
  const value = String(raw || '').trim();
  if (!value) return '';
  if (value.startsWith('http://') || value.startsWith('https://')) {
    try {
      const parsed = new URL(value);
      return (parsed.pathname.split('/').filter(Boolean)[0] || '').trim();
    } catch {
      return '';
    }
  }
  return value.replace(/^\/+|\/+$/g, '');
}

function isValidBarkKey(key) {
  return /^[a-zA-Z0-9_-]{4,128}$/.test(key);
}

function isValidVkToken(token) {
  return typeof token === 'string' && token.length >= 20 && token.length <= 512 && !/\s/.test(token);
}

function safeHttpsUrl(url) {
  if (!url || typeof url !== 'string') return '';
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' ? parsed.toString() : '';
  } catch {
    return '';
  }
}

function decodeVkText(raw) {
  return String(raw || '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'")
    .trim();
}

// Нативный диплинк, открывающий ИМЕННО iOS-приложение ВК (минуя Safari)
function buildVkDeepLink(peerId) {
  if (peerId > 2_000_000_000) {
    return `vk://vk.com/im?sel=c${peerId - 2_000_000_000}`;
  }
  if (peerId > 0 && peerId < 2_000_000_000) {
    return `vk://vk.com/im?sel=${peerId}`;
  }
  if (peerId < 0) {
    return `vk://vk.com/im?sel=${peerId}`;
  }
  return 'vk://vk.com/im';
}

function formatAttachmentFallback(extra) {
  if (!extra || typeof extra !== 'object') {
    return '📷 Фото / 🎤 Голосовое / Вложение';
  }
  const type = extra.attach1_type || '';
  const kind = extra.attach1_kind || '';

  if (type === 'photo') return '📷 Фотография';
  if (type === 'audio_message' || (type === 'doc' && kind === 'audiomsg')) {
    return '🎤 Голосовое сообщение';
  }
  if (type === 'sticker') return 'Стикер';
  if (type === 'video') return 'Видеозапись';
  if (type === 'audio') return 'Аудиозапись';
  if (type === 'doc') return 'Документ';
  if (type === 'wall' || type === 'wall_reply') return 'Запись со стены';
  if (type === 'gift') return 'Подарок';
  if (extra.fwd) return 'Пересланное сообщение';
  if (extra.geo) return 'Геопозиция';

  return '📷 Фото / 🎤 Голосовое / Вложение';
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      resolve();
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

// ---------------- Встроенный генератор ZIP (без сторонних пакетов) ----------------

const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[i] = c >>> 0;
}

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createZipBuffer(files) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const file of files) {
    const nameBuf = Buffer.from(file.name, 'utf8');
    const dataBuf = Buffer.isBuffer(file.content) ? file.content : Buffer.from(file.content, 'utf8');
    const checksum = crc32(dataBuf);
    const size = dataBuf.length;

    // Local File Header (30 bytes + filename)
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
    localHeader.writeUInt16LE(0, 8); // compression method: 0 (store)
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0, 12); // mod date
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(size, 18);
    localHeader.writeUInt32LE(size, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28); // extra len

    localParts.push(localHeader, nameBuf, dataBuf);

    // Central Directory Header (46 bytes + filename)
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // signature
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0x0800, 8); // UTF-8 flag
    centralHeader.writeUInt16LE(0, 10); // method: store
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(size, 20);
    centralHeader.writeUInt32LE(size, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + dataBuf.length;
  }

  const centralDirBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // End of Central Directory signature
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirBuf, eocd]);
}

// ---------------- Отправка пуша в Bark ----------------

async function sendBarkPush(barkKey, { title, body, icon, url, group }) {
  if (!isValidBarkKey(barkKey)) {
    throw new Error('Некорректный BARK_KEY (скопируйте ключ из приложения Bark)');
  }

  const payload = {
    title,
    body,
    url,
    group,
    level: 'active',
  };
  if (icon) {
    payload.icon = icon;
  }

  const t0 = performance.now();
  const res = await fetch(`https://api.day.app/${encodeURIComponent(barkKey)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(10_000),
  });
  const latencyMs = Math.round(performance.now() - t0);

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Bark вернул HTTP ${res.status}: ${text.slice(0, 120)}`);
  }

  try {
    const json = JSON.parse(text);
    if (typeof json.code === 'number' && json.code !== 200) {
      throw new Error(`Bark ошибка ${json.code}: ${json.message || 'проверьте BARK_KEY'}`);
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('Bark ошибка')) {
      throw err;
    }
  }

  totalSentAll += 1;
  return latencyMs;
}

// ---------------- Класс одного подключения VK -> Bark ----------------

class UserVkBridge {
  constructor({ sessionId, vkToken, barkKey, isEnvDefault = false }) {
    this.sessionId = sessionId;
    this.vkToken = vkToken;
    this.barkKey = barkKey;
    this.isEnvDefault = isEnvDefault;

    this.status = 'connecting'; // 'active' | 'connecting' | 'error' | 'stopped'
    this.error = null;
    this.vkUserId = null;
    this.accountName = null;
    this.sentCount = 0;
    this.connectedAt = Date.now();
    this.cache = new Map();
    this.abortController = new AbortController();
  }

  cacheGet(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    if (Date.now() > item.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    return item.value;
  }

  cacheSet(key, value) {
    if (this.cache.size >= 1000) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
  }

  async callVkApi(method, params = {}) {
    const form = new URLSearchParams({
      v: VK_API_VERSION,
      access_token: this.vkToken,
    });
    for (const [k, v] of Object.entries(params)) {
      form.set(k, String(v));
    }

    const combinedSignal = AbortSignal.any([
      this.abortController.signal,
      AbortSignal.timeout(15_000),
    ]);

    const res = await fetch(`https://api.vk.com/method/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: form.toString(),
      signal: combinedSignal,
    });

    if (!res.ok) {
      throw new Error(`VK API HTTP ${res.status}`);
    }

    const data = await res.json();
    if (data.error) {
      if (data.error.error_code === 5) {
        throw new Error('Неверный или истекший VK_TOKEN (код 5)');
      }
      if (data.error.error_code === 15) {
        throw new Error('У токена нет прав на чтение сообщений (код 15). Выберите Kate Mobile или VK Me.');
      }
      throw new Error(`VK API ошибка ${data.error.error_code}: ${data.error.error_msg}`);
    }

    return data.response;
  }

  async getSenderInfo(id) {
    const key = `sender:${id}`;
    const cached = this.cacheGet(key);
    if (cached) return cached;

    try {
      if (id > 0) {
        const users = await this.callVkApi('users.get', { user_ids: id, fields: 'photo_100' });
        if (users?.[0]) {
          const info = {
            name: `${users[0].first_name} ${users[0].last_name}`.trim(),
            icon: safeHttpsUrl(users[0].photo_100),
          };
          this.cacheSet(key, info);
          return info;
        }
      } else if (id < 0) {
        const resp = await this.callVkApi('groups.getById', { group_id: Math.abs(id) });
        const list = Array.isArray(resp) ? resp : resp?.groups || [];
        if (list[0]) {
          const info = {
            name: list[0].name,
            icon: safeHttpsUrl(list[0].photo_100),
          };
          this.cacheSet(key, info);
          return info;
        }
      }
    } catch {
      // Запасное имя
    }

    return {
      name: id < 0 ? `Сообщество #${Math.abs(id)}` : `Пользователь #${id}`,
      icon: '',
    };
  }

  async getChatInfo(peerId) {
    const key = `chat:${peerId}`;
    const cached = this.cacheGet(key);
    if (cached) return cached;

    try {
      const resp = await this.callVkApi('messages.getConversationsById', { peer_ids: peerId });
      const settings = resp?.items?.[0]?.chat_settings;
      if (settings?.title) {
        const info = {
          title: settings.title,
          icon: safeHttpsUrl(settings.photo?.photo_100),
        };
        this.cacheSet(key, info);
        return info;
      }
    } catch {
      // Запасное имя беседы
    }

    return { title: `Беседа #${peerId - 2_000_000_000}`, icon: '' };
  }

  async handleMessageUpdate(update) {
    const flags = Number(update[2] || 0);
    // Игнорируем исходящие сообщения (флаг 2)
    if ((flags & 2) !== 0) return;

    const peerId = Number(update[3] || 0);
    if (!Number.isSafeInteger(peerId) || peerId === 0) return;

    const rawText = update[5];
    const extra = update[6] && typeof update[6] === 'object' ? update[6] : {};

    let title = '';
    let icon = '';

    if (peerId > 2_000_000_000) {
      const fromId = Number(extra.from || 0);
      const [chat, sender] = await Promise.all([
        this.getChatInfo(peerId),
        fromId !== 0 ? this.getSenderInfo(fromId) : Promise.resolve(null),
      ]);
      title = sender ? `${chat.title}: ${sender.name}` : chat.title;
      icon = sender?.icon || chat.icon;
    } else {
      const sender = await this.getSenderInfo(peerId);
      title = sender.name;
      icon = sender.icon;
    }

    const body = decodeVkText(rawText) || formatAttachmentFallback(extra);
    const url = buildVkDeepLink(peerId);

    try {
      const ms = await sendBarkPush(this.barkKey, {
        title,
        body,
        icon,
        url,
        group: `vk_${peerId}`,
      });
      this.sentCount += 1;
      console.log(`[PUSH OK] ${this.accountName || 'user'} <- ${title} (${ms} ms)`);
    } catch (err) {
      console.error(`[PUSH ERROR] ${err.message}`);
    }
  }

  async verifyAndStart() {
    // Проверяем токен и права на messages.getLongPollServer до возврата ответа пользователю
    const [me, lp] = await Promise.all([
      this.callVkApi('users.get'),
      this.callVkApi('messages.getLongPollServer', { lp_version: 3, need_pts: 0 }),
    ]);

    if (me?.[0]) {
      this.vkUserId = me[0].id;
      this.accountName = `${me[0].first_name} ${me[0].last_name}`.trim();
    }

    const initialCreds = {
      server: String(lp.server).replace(/^https?:\/\//, ''),
      key: lp.key,
      ts: lp.ts,
    };

    this.status = 'active';
    this.error = null;
    this.runLoop(initialCreds);
  }

  startBackground() {
    this.runLoop(null);
  }

  async runLoop(initialCreds) {
    let creds = initialCreds;
    let retryDelayMs = 2000;
    const signal = this.abortController.signal;

    if (!this.accountName) {
      try {
        const me = await this.callVkApi('users.get');
        if (me?.[0]) {
          this.vkUserId = me[0].id;
          this.accountName = `${me[0].first_name} ${me[0].last_name}`.trim();
        }
      } catch {
        // обработается в основном цикле
      }
    }

    while (!signal.aborted) {
      try {
        if (!creds) {
          this.status = 'connecting';
          const lp = await this.callVkApi('messages.getLongPollServer', {
            lp_version: 3,
            need_pts: 0,
          });
          creds = {
            server: String(lp.server).replace(/^https?:\/\//, ''),
            key: lp.key,
            ts: lp.ts,
          };
          this.status = 'active';
          this.error = null;
          retryDelayMs = 2000;
        }

        const pollUrl = new URL(`https://${creds.server}`);
        pollUrl.searchParams.set('act', 'a_check');
        pollUrl.searchParams.set('key', creds.key);
        pollUrl.searchParams.set('ts', String(creds.ts));
        pollUrl.searchParams.set('wait', '25');
        pollUrl.searchParams.set('mode', '202');
        pollUrl.searchParams.set('version', '3');

        const res = await fetch(pollUrl.toString(), {
          signal: AbortSignal.any([signal, AbortSignal.timeout(35_000)]),
        });

        if (!res.ok) {
          throw new Error(`Long Poll HTTP ${res.status}`);
        }

        const data = await res.json();

        if (data.failed) {
          if (data.failed === 1 && data.ts) {
            creds.ts = data.ts;
            continue;
          }
          if (data.failed === 2) {
            const oldTs = creds.ts;
            const refreshed = await this.callVkApi('messages.getLongPollServer', {
              lp_version: 3,
              need_pts: 0,
            });
            creds = {
              server: String(refreshed.server).replace(/^https?:\/\//, ''),
              key: refreshed.key,
              ts: oldTs || refreshed.ts,
            };
            continue;
          }
          creds = null;
          continue;
        }

        if (data.ts) creds.ts = data.ts;
        this.status = 'active';
        this.error = null;
        retryDelayMs = 2000;

        if (Array.isArray(data.updates)) {
          for (const update of data.updates) {
            if (Array.isArray(update) && update[0] === 4) {
              this.handleMessageUpdate(update).catch((err) => {
                console.error('[HANDLE ERROR]', err.message);
              });
            }
          }
        }
      } catch (err) {
        if (signal.aborted) break;
        const message = err instanceof Error ? err.message : 'Сетевая ошибка Long Poll';
        this.status = 'error';
        this.error = message;
        creds = null;

        const isAuthError = message.includes('(код 5)') || message.includes('(код 15)');
        await sleep(isAuthError ? 60_000 : retryDelayMs, signal);
        retryDelayMs = Math.min(retryDelayMs * 2, 30_000);
      }
    }
  }

  stop() {
    this.status = 'stopped';
    this.abortController.abort();
  }

  toPublicStatus() {
    return {
      status: this.status,
      error: this.error,
      accountName: this.accountName,
      sentCount: this.sentCount,
      uptimeMs: Date.now() - this.connectedAt,
    };
  }
}

// Автозапуск дефолтного моста, если VK_TOKEN и BARK_KEY заданы в Environment Variables (Render.com)
const ENV_VK_TOKEN = (process.env.VK_TOKEN || '').trim();
const ENV_BARK_KEY = extractBarkKey(process.env.BARK_KEY);
let envBridge = null;

if (isValidVkToken(ENV_VK_TOKEN) && isValidBarkKey(ENV_BARK_KEY)) {
  envBridge = new UserVkBridge({
    sessionId: 'env-default',
    vkToken: ENV_VK_TOKEN,
    barkKey: ENV_BARK_KEY,
    isEnvDefault: true,
  });
  bridges.set('env-default', envBridge);
  envBridge.startBackground();
}

// ---------------- Веб-сервер Express ----------------

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

function getSessionFromHeader(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  const id = auth.slice(7).trim();
  if (!id || id === 'env-default') return null;
  return bridges.get(id) || null;
}

// 1. Эндпоинт для бесплатного cron-job.org (чтобы Render не засыпал)
app.get('/ping', (_req, res) => {
  res.type('text/plain').send('OK');
});

// 2. Кнопка скачивания готового ZIP-архива (ровно 2 файла: package.json и index.js)
app.get('/download/zip', (_req, res) => {
  try {
    const rootDir = process.cwd();
    const pkgContent = fs.readFileSync(path.join(rootDir, 'package.json'));
    const idxContent = fs.readFileSync(path.join(rootDir, 'index.js'));

    const zipBuf = createZipBuffer([
      { name: 'package.json', content: pkgContent },
      { name: 'index.js', content: idxContent },
    ]);

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="vk-bark-bridge.zip"');
    res.setHeader('Content-Length', String(zipBuf.length));
    res.send(zipBuf);
  } catch (err) {
    res.status(500).json({ error: 'Не удалось собрать ZIP-архив' });
  }
});

// 3. Общий статус сервера + личный статус сессии (если передан Bearer sessionId)
app.get('/api/status', (req, res) => {
  const sessionBridge = getSessionFromHeader(req);
  const activeCount = Array.from(bridges.values()).filter((b) => b.status === 'active').length;

  res.json({
    serverUptimeMs: Date.now() - startedAt,
    activeBridges: activeCount,
    totalBridges: bridges.size,
    totalSentAll,
    envBridge: envBridge ? envBridge.toPublicStatus() : null,
    myBridge: sessionBridge ? sessionBridge.toPublicStatus() : null,
  });
});

// 4. Подключение нового пользователя прямо через сайт (ввод своих VK_TOKEN и BARK_KEY)
app.post('/api/connect', async (req, res) => {
  try {
    const vkToken = String(req.body?.vkToken || '').trim();
    const barkKey = extractBarkKey(req.body?.barkKey);

    if (!isValidVkToken(vkToken)) {
      res.status(400).json({ error: 'Введите корректный VK_TOKEN (начинается с vk1.a....)' });
      return;
    }
    if (!isValidBarkKey(barkKey)) {
      res.status(400).json({ error: 'Введите корректный BARK_KEY из приложения Bark на iPhone' });
      return;
    }
    if (bridges.size >= MAX_BRIDGES) {
      res.status(429).json({
        error: 'Достигнут лимит активных подключений на этом сервере. Скачайте ZIP и запустите свою копию на Render.',
      });
      return;
    }

    const sessionId = crypto.randomBytes(24).toString('hex');
    const instance = new UserVkBridge({ sessionId, vkToken, barkKey });

    // Проверяем токен прямо сейчас, чтобы пользователь сразу увидел результат или точную ошибку
    await instance.verifyAndStart();

    // Если этот же аккаунт ВК уже был подключен ранее — останавливаем дубликат
    if (instance.vkUserId) {
      for (const [oldId, existing] of bridges.entries()) {
        if (!existing.isEnvDefault && existing.vkUserId === instance.vkUserId) {
          existing.stop();
          bridges.delete(oldId);
        }
      }
    }

    bridges.set(sessionId, instance);
    res.json({
      ok: true,
      sessionId,
      myBridge: instance.toPublicStatus(),
    });
  } catch (err) {
    res.status(400).json({
      error: err instanceof Error ? err.message : 'Не удалось подключиться к ВКонтакте',
    });
  }
});

// 5. Отключение своего подключения
app.post('/api/disconnect', (req, res) => {
  const sessionBridge = getSessionFromHeader(req);
  if (sessionBridge) {
    sessionBridge.stop();
    bridges.delete(sessionBridge.sessionId);
  }
  res.json({ ok: true });
});

// 6. Тестовый пуш в Bark со ссылкой vk://vk.com/im
app.post('/api/test', async (req, res) => {
  try {
    const sessionBridge = getSessionFromHeader(req);
    const inputBarkKey = extractBarkKey(req.body?.barkKey);
    const barkKeyToUse =
      inputBarkKey || sessionBridge?.barkKey || (envBridge ? envBridge.barkKey : '');

    if (!isValidBarkKey(barkKeyToUse)) {
      res.status(400).json({
        ok: false,
        error: 'Введите ваш BARK_KEY в поле выше (или задайте BARK_KEY в настройках Render)',
      });
      return;
    }

    const latencyMs = await sendBarkPush(barkKeyToUse, {
      title: 'VK → Bark тест',
      body: 'Нажмите на уведомление — откроется нативное приложение ВК на iPhone',
      icon: '',
      url: 'vk://vk.com/im',
      group: 'vk_test',
    });

    if (sessionBridge) sessionBridge.sentCount += 1;
    else if (envBridge && barkKeyToUse === envBridge.barkKey) envBridge.sentCount += 1;

    res.json({ ok: true, latencyMs });
  } catch (err) {
    res.status(400).json({
      ok: false,
      error: err instanceof Error ? err.message : 'Не удалось отправить тестовый пуш',
    });
  }
});

// 7. Главная страница: ввод ключей, статус, скачивание ZIP и подробная инструкция прямо на сайте
app.get('/', (_req, res) => {
  const html = `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>VK → Bark Push Bridge — Нативные уведомления ВК на iPhone</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      background: #000000;
      color: #F5F5F7;
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
      line-height: 1.5;
    }
    a { color: #0A84FF; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace;
      font-size: 0.92em;
    }
    .topbar {
      position: sticky;
      top: 0;
      z-index: 10;
      background: rgba(0, 0, 0, 0.85);
      backdrop-filter: blur(16px);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .topbar-inner {
      max-width: 980px;
      margin: 0 auto;
      padding: 0 20px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .brand {
      font-size: 16px;
      font-weight: 700;
      color: #FFFFFF;
      white-space: nowrap;
    }
    .nav {
      display: flex;
      align-items: center;
      gap: 20px;
      font-size: 14px;
    }
    .nav a { color: #98989F; white-space: nowrap; }
    .nav a:hover { color: #FFFFFF; text-decoration: none; }
    .btn-zip {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 8px 14px;
      border-radius: 10px;
      background: #242426;
      border: 1px solid rgba(255, 255, 255, 0.14);
      color: #F5F5F7;
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
      transition: background 150ms ease;
    }
    .btn-zip:hover { background: #323236; text-decoration: none; }
    .wrap {
      max-width: 980px;
      margin: 0 auto;
      padding: 28px 20px 64px;
    }
    .hero {
      max-width: 680px;
      margin-bottom: 24px;
    }
    .hero h1 {
      font-size: clamp(24px, 4vw, 32px);
      font-weight: 700;
      letter-spacing: -0.02em;
      line-height: 1.2;
    }
    .hero p {
      margin-top: 8px;
      font-size: 14px;
      color: #98989F;
    }
    .status-strip {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      padding: 16px 20px;
      border-radius: 16px;
      background: #161618;
      border: 1px solid rgba(255, 255, 255, 0.09);
      margin-bottom: 24px;
    }
    .stat-label { font-size: 12px; color: #8E8E93; }
    .stat-val {
      margin-top: 3px;
      font-size: 15px;
      font-weight: 600;
      font-variant-numeric: tabular-nums;
    }
    .grid {
      display: grid;
      grid-template-columns: 1.05fr 0.95fr;
      gap: 20px;
      align-items: start;
    }
    .card {
      background: #161618;
      border: 1px solid rgba(255, 255, 255, 0.09);
      border-radius: 18px;
      overflow: hidden;
    }
    .card-head {
      padding: 18px 20px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .card-head h2 { font-size: 17px; font-weight: 600; }
    .card-head p { margin-top: 4px; font-size: 13px; color: #98989F; }
    .card-body { padding: 20px; }
    .field { margin-bottom: 16px; }
    .field:last-of-type { margin-bottom: 0; }
    .field label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #E5E5EA;
      margin-bottom: 6px;
    }
    .input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 11px 42px 11px 13px;
      border-radius: 11px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      background: #242426;
      color: #F5F5F7;
      font-size: 13px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      outline: none;
      transition: border-color 150ms ease;
    }
    input:focus { border-color: #0A84FF; }
    input::placeholder {
      color: #636366;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .eye-btn {
      position: absolute;
      right: 8px;
      background: transparent;
      border: none;
      color: #8E8E93;
      cursor: pointer;
      padding: 6px;
      font-size: 12px;
      border-radius: 7px;
    }
    .eye-btn:hover { color: #FFFFFF; }
    .hint {
      margin-top: 6px;
      font-size: 12px;
      color: #8E8E93;
    }
    .btn-row {
      margin-top: 18px;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .btn {
      flex: 1 1 auto;
      padding: 12px 16px;
      border: none;
      border-radius: 11px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 150ms ease, opacity 150ms ease;
      white-space: nowrap;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #0A84FF; color: #FFFFFF; }
    .btn-primary:hover { background: #1E90FF; }
    .btn-secondary {
      background: #2C2C2E;
      color: #F5F5F7;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .btn-secondary:hover { background: #3A3A3C; }
    .btn-danger {
      background: rgba(255, 69, 58, 0.14);
      color: #FF453A;
      border: 1px solid rgba(255, 69, 58, 0.3);
    }
    .btn-danger:hover { background: rgba(255, 69, 58, 0.22); }
    .msg {
      margin-top: 14px;
      font-size: 13px;
      line-height: 1.45;
      min-height: 18px;
    }
    .msg.ok { color: #30D158; }
    .msg.err { color: #FF453A; }
    .session-box {
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid rgba(255, 255, 255, 0.08);
      display: none;
    }
    .session-row {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      padding: 6px 0;
      font-size: 13px;
    }
    .steps {
      list-style: none;
      display: flex;
      flex-direction: column;
    }
    .step {
      padding: 16px 20px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.07);
    }
    .step:last-child { border-bottom: none; }
    .step-title {
      font-size: 14px;
      font-weight: 600;
      color: #FFFFFF;
      margin-bottom: 6px;
    }
    .step p, .step li {
      font-size: 13px;
      color: #AEAEB2;
      line-height: 1.55;
    }
    .step ul {
      margin-top: 6px;
      padding-left: 18px;
    }
    .code-line {
      margin-top: 8px;
      padding: 9px 11px;
      border-radius: 10px;
      background: #0D0D0F;
      border: 1px solid rgba(255, 255, 255, 0.08);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      color: #D1D1D6;
      word-break: break-all;
    }
    .hl { color: #30D158; font-weight: 600; }
    .deploy-card {
      margin-top: 24px;
    }
    .deploy-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 20px;
      padding: 20px;
    }
    .deploy-col h3 {
      font-size: 14px;
      font-weight: 600;
      margin-bottom: 8px;
      color: #FFFFFF;
    }
    .deploy-col ol {
      padding-left: 18px;
      font-size: 13px;
      color: #AEAEB2;
    }
    .deploy-col li { margin-bottom: 6px; }
    @media (max-width: 820px) {
      .nav { display: none; }
      .status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .grid { grid-template-columns: 1fr; }
      .deploy-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">VK → Bark Push Bridge</div>
      <nav class="nav">
        <a href="#connect">Подключение</a>
        <a href="#guide">Инструкция</a>
        <a href="#selfhost">Свой сервер на Render</a>
      </nav>
      <a class="btn-zip" href="/download/zip" download="vk-bark-bridge.zip">
        ⬇ Скачать ZIP (2 файла)
      </a>
    </div>
  </header>

  <main class="wrap">
    <section class="hero">
      <h1>Нативные Push-уведомления ВКонтакте на iPhone</h1>
      <p>
        Подключите свой аккаунт ВК и приложение <strong>Bark</strong> прямо здесь — новые сообщения будут мгновенно приходить на iPhone через родной Apple APNs и при нажатии открывать приложение ВК (<span class="mono">vk://</span>), а не Safari.
      </p>
    </section>

    <section class="status-strip" aria-label="Статус сервера">
      <div>
        <div class="stat-label">Статус сервера</div>
        <div id="srvStatus" class="stat-val" style="color:#30D158">🟢 Работает</div>
      </div>
      <div>
        <div class="stat-label">Активных подключений</div>
        <div id="srvActive" class="stat-val mono">0</div>
      </div>
      <div>
        <div class="stat-label">Отправлено пушей</div>
        <div id="srvSent" class="stat-val mono">0</div>
      </div>
      <div>
        <div class="stat-label">Время работы</div>
        <div id="srvUptime" class="stat-val mono">00:00:00</div>
      </div>
    </section>

    <div class="grid">
      <!-- Левая колонка: ввод ключей для любого пользователя -->
      <section id="connect" class="card">
        <div class="card-head">
          <h2>Подключить свой iPhone</h2>
          <p>Введите ваши ключи (где их взять за 1 минуту — справа в инструкции).</p>
        </div>
        <div class="card-body">
          <div class="field">
            <label for="barkKey">1. BARK_KEY (ключ из приложения Bark на iPhone)</label>
            <div class="input-wrap">
              <input id="barkKey" type="text" autocomplete="off" spellcheck="false" placeholder="Например: AbCdEf123456 или вся ссылка https://api.day.app/..." />
            </div>
            <div class="hint">Можно вставить всю ссылку из Bark — ключ вырежется автоматически.</div>
          </div>

          <div class="field">
            <label for="vkToken">2. VK_TOKEN (токен ВКонтакте с доступом к сообщениям)</label>
            <div class="input-wrap">
              <input id="vkToken" type="password" autocomplete="off" spellcheck="false" placeholder="vk1.a.xxxxxxxxxxxxxxxxxxxxxxxx..." />
              <button id="toggleVk" type="button" class="eye-btn">Показать</button>
            </div>
            <div class="hint">Хранится только в оперативной памяти сервера для Long Poll и никому не показывается.</div>
          </div>

          <div class="btn-row">
            <button id="connectBtn" type="button" class="btn btn-primary">Подключить уведомления</button>
            <button id="testBtn" type="button" class="btn btn-secondary">Тестовый пуш в Bark</button>
          </div>

          <div id="feedback" class="msg"></div>

          <div id="sessionBox" class="session-box">
            <div class="session-row">
              <span style="color:#98989F">Ваше подключение</span>
              <span id="myStatus" style="font-weight:600">🟢 Работает</span>
            </div>
            <div class="session-row">
              <span style="color:#98989F">Аккаунт ВК</span>
              <span id="myAccount" style="font-weight:600">—</span>
            </div>
            <div class="session-row">
              <span style="color:#98989F">Доставлено вам пушей</span>
              <span id="mySent" class="mono" style="font-weight:600">0</span>
            </div>
            <div id="myError" class="msg err" style="display:none;margin-top:8px"></div>
            <div class="btn-row" style="margin-top:12px">
              <button id="disconnectBtn" type="button" class="btn btn-danger">Отключить мой мост</button>
            </div>
          </div>
        </div>
      </section>

      <!-- Правая колонка: пошаговая инструкция прямо на сайте -->
      <section id="guide" class="card">
        <div class="card-head">
          <h2>Инструкция: откуда взять 2 ключа</h2>
          <p>Занимает 2 минуты прямо с iPhone или компьютера.</p>
        </div>
        <ol class="steps">
          <li class="step">
            <div class="step-title">Шаг 1. Скачать Bark и взять BARK_KEY</div>
            <p>Установите бесплатное приложение <strong>Bark</strong> из App Store, откройте его и нажмите <strong>«Разрешить уведомления»</strong>. На главном экране скопируйте ключ из ссылки:</p>
            <div class="code-line">https://api.day.app/<span class="hl">AbCdEf123456GhIjKl</span>/текст</div>
            <p style="margin-top:6px">Вставьте выделенную часть (или всю ссылку целиком) в поле <strong>BARK_KEY</strong> слева.</p>
          </li>

          <li class="step">
            <div class="step-title">Шаг 2. Получить VK_TOKEN</div>
            <ul>
              <li>Откройте <a href="https://vkhost.github.io" target="_blank" rel="noopener noreferrer">vkhost.github.io</a> и выберите <strong>Kate Mobile</strong> (или <strong>VK Me</strong>).</li>
              <li>Нажмите <strong>«Разрешить»</strong> в ВК — вас перекинет на пустую страницу.</li>
              <li>Скопируйте из адресной строки всё между <span class="mono">access_token=</span> и <span class="mono">&amp;expires_in</span>:</li>
            </ul>
            <div class="code-line">...#access_token=<span class="hl">vk1.a.длинная_строка</span>&amp;expires_in=0...</div>
          </li>

          <li class="step">
            <div class="step-title">Шаг 3. Проверить переход в приложение ВК</div>
            <p>Вставьте оба ключа в форму слева → нажмите <strong>«Тестовый пуш в Bark»</strong> → тапните по пришедшему пушу на iPhone. iOS сразу откроет родное приложение ВК (<span class="mono">vk://vk.com/im</span>) без Safari. Затем нажмите <strong>«Подключить уведомления»</strong>.</p>
          </li>
        </ol>
      </section>
    </div>

    <!-- Нижний блок: как скачать ZIP и запустить свой бесплатный сервер на Render.com -->
    <section id="selfhost" class="card deploy-card">
      <div class="card-head" style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px">
        <div>
          <h2>Запустить свою бесплатную копию 24/7 на Render.com</h2>
          <p>Весь проект — ровно 2 файла (<span class="mono">package.json</span> и <span class="mono">index.js</span>). Скачайте архив и задеплойте за 2 минуты.</p>
        </div>
        <a class="btn-zip" href="/download/zip" download="vk-bark-bridge.zip">
          ⬇ Скачать vk-bark-bridge.zip
        </a>
      </div>
      <div class="deploy-grid">
        <div class="deploy-col">
          <h3>1. Залить архив на GitHub</h3>
          <ol>
            <li>Нажмите <strong>«Скачать vk-bark-bridge.zip»</strong> и распакуйте 2 файла.</li>
            <li>На <a href="https://github.com" target="_blank" rel="noopener noreferrer">github.com</a> создайте новый <strong>Private</strong> репозиторий <span class="mono">vk-bark-bridge</span>.</li>
            <li>Нажмите <strong>uploading an existing file</strong> и перетащите туда <span class="mono">package.json</span> и <span class="mono">index.js</span> → <strong>Commit changes</strong>.</li>
          </ol>
        </div>

        <div class="deploy-col">
          <h3>2. Деплой на Render.com (Free)</h3>
          <ol>
            <li>На <a href="https://render.com" target="_blank" rel="noopener noreferrer">render.com</a> нажмите <strong>New + → Web Service</strong> и подключите репозиторий.</li>
            <li><strong>Build Command:</strong> <span class="mono">npm install</span><br /><strong>Start Command:</strong> <span class="mono">npm start</span><br /><strong>Plan:</strong> Free ($0/month).</li>
            <li>В <strong>Environment Variables</strong> (для автозапуска при старте) добавьте <span class="mono">VK_TOKEN</span> и <span class="mono">BARK_KEY</span> → <strong>Deploy</strong>.</li>
          </ol>
        </div>

        <div class="deploy-col">
          <h3>3. Чтобы сервер не засыпал (cron-job.org)</h3>
          <ol>
            <li>Зайдите на бесплатный <a href="https://cron-job.org" target="_blank" rel="noopener noreferrer">cron-job.org</a> → <strong>Create Cronjob</strong>.</li>
            <li>Вставьте URL вашего сервера с <span class="mono">/ping</span> на конце (<a href="/ping" target="_blank" rel="noopener noreferrer">проверить /ping</a>).</li>
            <li>Интервал: <strong>Every 5 minutes</strong> → <strong>Create</strong>. Сервер будет работать круглосуточно.</li>
          </ol>
        </div>
      </div>
    </section>
  </main>

  <script>
    const startedAtMs = ${startedAt};
    let currentSessionId = null;

    const srvStatusEl = document.getElementById('srvStatus');
    const srvActiveEl = document.getElementById('srvActive');
    const srvSentEl = document.getElementById('srvSent');
    const srvUptimeEl = document.getElementById('srvUptime');

    const barkKeyInput = document.getElementById('barkKey');
    const vkTokenInput = document.getElementById('vkToken');
    const toggleVkBtn = document.getElementById('toggleVk');
    const connectBtn = document.getElementById('connectBtn');
    const testBtn = document.getElementById('testBtn');
    const disconnectBtn = document.getElementById('disconnectBtn');
    const feedbackEl = document.getElementById('feedback');

    const sessionBox = document.getElementById('sessionBox');
    const myStatusEl = document.getElementById('myStatus');
    const myAccountEl = document.getElementById('myAccount');
    const mySentEl = document.getElementById('mySent');
    const myErrorEl = document.getElementById('myError');

    function fmtUptime(ms) {
      const s = Math.max(0, Math.floor(ms / 1000));
      const d = Math.floor(s / 86400);
      const h = String(Math.floor((s % 86400) / 3600)).padStart(2, '0');
      const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
      const sec = String(s % 60).padStart(2, '0');
      return d > 0 ? d + 'д ' + h + ':' + m + ':' + sec : h + ':' + m + ':' + sec;
    }

    function setFeedback(text, type) {
      feedbackEl.className = 'msg ' + (type || '');
      feedbackEl.textContent = text;
    }

    function renderMyBridge(info) {
      if (!info) {
        sessionBox.style.display = 'none';
        return;
      }
      sessionBox.style.display = 'block';
      myAccountEl.textContent = info.accountName || 'Подключено';
      mySentEl.textContent = String(info.sentCount || 0);
      if (info.status === 'active') {
        myStatusEl.textContent = '🟢 Работает (Long Poll активен)';
        myStatusEl.style.color = '#30D158';
      } else if (info.status === 'error') {
        myStatusEl.textContent = '🔴 Ошибка';
        myStatusEl.style.color = '#FF453A';
      } else {
        myStatusEl.textContent = '🟡 Подключение…';
        myStatusEl.style.color = '#FF9F0A';
      }
      if (info.error) {
        myErrorEl.textContent = info.error;
        myErrorEl.style.display = 'block';
      } else {
        myErrorEl.style.display = 'none';
      }
    }

    toggleVkBtn.addEventListener('click', () => {
      const hidden = vkTokenInput.type === 'password';
      vkTokenInput.type = hidden ? 'text' : 'password';
      toggleVkBtn.textContent = hidden ? 'Скрыть' : 'Показать';
    });

    async function refreshStatus() {
      try {
        const headers = currentSessionId ? { Authorization: 'Bearer ' + currentSessionId } : {};
        const res = await fetch('/api/status', { headers });
        if (!res.ok) return;
        const data = await res.json();
        srvActiveEl.textContent = String(data.activeBridges);
        srvSentEl.textContent = String(data.totalSentAll);

        if (data.envBridge && !data.myBridge) {
          if (data.envBridge.status === 'error') {
            srvStatusEl.textContent = '🔴 Ошибка (env)';
            srvStatusEl.style.color = '#FF453A';
          } else if (data.envBridge.status === 'active') {
            srvStatusEl.textContent = '🟢 Работает (env)';
            srvStatusEl.style.color = '#30D158';
          }
        } else {
          srvStatusEl.textContent = data.activeBridges > 0 ? '🟢 Работает' : '🟡 Ожидает ключи';
          srvStatusEl.style.color = data.activeBridges > 0 ? '#30D158' : '#FF9F0A';
        }

        if (data.myBridge) {
          renderMyBridge(data.myBridge);
        }
      } catch {}
    }

    setInterval(() => {
      srvUptimeEl.textContent = fmtUptime(Date.now() - startedAtMs);
    }, 1000);
    setInterval(refreshStatus, 5000);
    refreshStatus();

    connectBtn.addEventListener('click', async () => {
      const vkToken = vkTokenInput.value.trim();
      const barkKey = barkKeyInput.value.trim();
      if (!barkKey || !vkToken) {
        setFeedback('Заполните оба поля: BARK_KEY и VK_TOKEN.', 'err');
        return;
      }
      connectBtn.disabled = true;
      connectBtn.textContent = 'Подключение…';
      setFeedback('', '');
      try {
        const res = await fetch('/api/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ vkToken, barkKey }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || 'Не удалось подключить уведомления');
        }
        currentSessionId = data.sessionId;
        vkTokenInput.value = '';
        renderMyBridge(data.myBridge);
        setFeedback('Готово! Long Poll запущен. Новые сообщения из ВК сразу придут в Bark на ваш iPhone.', 'ok');
        refreshStatus();
      } catch (err) {
        setFeedback(err.message || 'Ошибка подключения', 'err');
      } finally {
        connectBtn.disabled = false;
        connectBtn.textContent = 'Подключить уведомления';
      }
    });

    testBtn.addEventListener('click', async () => {
      testBtn.disabled = true;
      testBtn.textContent = 'Отправка…';
      setFeedback('', '');
      try {
        const headers = { 'Content-Type': 'application/json' };
        if (currentSessionId) headers.Authorization = 'Bearer ' + currentSessionId;
        const res = await fetch('/api/test', {
          method: 'POST',
          headers,
          body: JSON.stringify({ barkKey: barkKeyInput.value.trim() }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          throw new Error(data.error || 'Не удалось отправить тестовый пуш');
        }
        setFeedback('Тестовый пуш доставлен за ' + data.latencyMs + ' мс! Нажмите на уведомление на iPhone — откроется приложение ВК.', 'ok');
        refreshStatus();
      } catch (err) {
        setFeedback(err.message || 'Ошибка отправки пуша', 'err');
      } finally {
        testBtn.disabled = false;
        testBtn.textContent = 'Тестовый пуш в Bark';
      }
    });

    disconnectBtn.addEventListener('click', async () => {
      if (!currentSessionId) return;
      await fetch('/api/disconnect', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + currentSessionId },
      });
      currentSessionId = null;
      renderMyBridge(null);
      setFeedback('Ваше подключение остановлено и удалено из памяти сервера.', 'ok');
      refreshStatus();
    });
  </script>
</body>
</html>`;

  res.type('text/html; charset=utf-8').send(html);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`VK -> Bark Bridge запущен на http://0.0.0.0:${PORT}`);
});
