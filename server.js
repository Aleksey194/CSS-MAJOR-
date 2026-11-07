// MAJOR CSS — сервер сайта v1.3 (база данных SQLite)
// Без внешних пакетов. Нужен Node.js 22.13 или новее (SQLite встроена в Node).
//
// Запуск:            node server.js
// Задать пароль:     node server.js set-password ЛОГИН ПАРОЛЬ
//
// Переменные окружения:
//   PORT=3000
//   SECURE=1          — если сайт работает по HTTPS
//   TRUST_PROXY=1     — если стоите за nginx / Cloudflare
//   ADMIN_PASSWORD=.. — пароль при первом запуске (иначе генерируется)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
function findPage() { // находит HTML сайта, даже если файл называется «major_css_site (2).html»
  const l = fs.readdirSync(__dirname).filter(n => /^major_css_site.*\.html$/i.test(n) || n === 'index.html');
  return path.join(__dirname, l.includes('major_css_site.html') ? 'major_css_site.html' : (l[0] || 'major_css_site.html'));
}
const DIR = __dirname, PAGE = findPage(), DB = path.join(DIR, 'data.json'), USERS = path.join(DIR, 'admins.json');
const PORT = +process.env.PORT || 3000;

process.on('uncaughtException', e => console.error('Ошибка:', e && e.message));
process.on('unhandledRejection', e => console.error('Ошибка:', e && e.message));
const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
process.removeAllListeners('warning'); // SQLite в Node помечена «экспериментальной» — убираем лишнее предупреждение
process.on('warning', w => { if (w.name !== 'ExperimentalWarning') console.warn(w); });
let DatabaseSync;
try { ({ DatabaseSync } = require('node:sqlite')); } catch { console.error('Нужен Node.js 22.13 или новее (там встроена SQLite). Сейчас: ' + process.version); process.exit(1); }
const DBFILE = path.join(DIR, 'major.db'), fresh = !fs.existsSync(DBFILE);
const sql = new DatabaseSync(DBFILE);
if (fresh) { try { fs.chmodSync(DBFILE, 0o600); } catch {} }
sql.exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS site (id INTEGER PRIMARY KEY CHECK (id = 1), json TEXT NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS admins (login TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, login TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS regs (
  id TEXT PRIMARY KEY, at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','accepted','rejected')),
  confirmed INTEGER NOT NULL DEFAULT 0, confirmed_at INTEGER, ctoken TEXT NOT NULL UNIQUE,
  team TEXT NOT NULL, team_norm TEXT NOT NULL, captain TEXT NOT NULL, contact TEXT NOT NULL, roster TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS regs_norm ON regs(team_norm);
CREATE INDEX IF NOT EXISTS regs_at ON regs(at DESC);
CREATE INDEX IF NOT EXISTS regs_contact ON regs(lower(contact));
CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, until INTEGER NOT NULL, reason TEXT, at INTEGER NOT NULL);`);
const norm = t => String(t).toLowerCase().replace(/\s+/g, ' ').trim();
if (!sql.prepare('PRAGMA table_info(regs)').all().some(c => c.name === 'consent_at')) sql.exec('ALTER TABLE regs ADD COLUMN consent_at INTEGER'); // когда дано согласие
const tx = fn => { sql.exec('BEGIN'); try { const r = fn(); sql.exec('COMMIT'); return r; } catch (e) { sql.exec('ROLLBACK'); throw e; } };
const getSite = () => { const r = sql.prepare('SELECT json FROM site WHERE id = 1').get(); return r ? JSON.parse(r.json) : null; };
const putSite = o => sql.prepare('INSERT INTO site (id, json, updated) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated = excluded.updated').run(JSON.stringify(o), Date.now());
const regRow = r => ({ id: r.id, at: r.at, status: r.status, confirmed: !!r.confirmed, confirmedAt: r.confirmed_at || undefined, ctoken: r.ctoken, team: r.team, captain: r.captain, contact: r.contact, roster: r.roster });
const allRegs = () => sql.prepare('SELECT * FROM regs ORDER BY at DESC').all().map(regRow);
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function setPassword(login, pw) { const salt = crypto.randomBytes(16).toString('hex'); sql.prepare('INSERT INTO admins (login, salt, hash) VALUES (?, ?, ?) ON CONFLICT(login) DO UPDATE SET salt = excluded.salt, hash = excluded.hash').run(login.toLowerCase(), salt, hashPw(pw, salt)); }

if (process.argv[2] === 'backup') { // node server.js backup — целая копия базы, можно при запущенном сервере
  const dir = path.join(DIR, 'backups'); fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, 'major-' + new Date().toISOString().slice(0, 10) + '.db'); try { fs.unlinkSync(f); } catch {}
  sql.exec("VACUUM INTO '" + f.replace(/'/g, "''") + "'"); console.log('Копия сохранена: ' + f); process.exit(0);
}
if (process.argv[2] === 'bans') { sql.prepare('SELECT ip, until, reason FROM bans WHERE until > ?').all(Date.now()).forEach(b => console.log(b.ip, '— до', new Date(b.until).toLocaleString('ru-RU'), '—', b.reason)); process.exit(0); }
if (process.argv[2] === 'unban') { sql.prepare('DELETE FROM bans WHERE ip = ?').run(String(process.argv[3] || '')); console.log('Готово.'); process.exit(0); }
if (process.argv[2] === 'set-password') {
  if (!process.argv[3] || !process.argv[4] || process.argv[4].length < 8) { console.log('Использование: node server.js set-password ЛОГИН ПАРОЛЬ (пароль от 8 символов)'); process.exit(1); }
  setPassword(process.argv[3], process.argv[4]); console.log('Пароль для «' + process.argv[3] + '» сохранён.'); process.exit(0);
}
if (!sql.prepare('SELECT COUNT(*) AS n FROM admins').get().n && !fs.existsSync(path.join(DIR, 'admins.json'))) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  setPassword('admin', pw); console.log('\nСоздан администратор.  Логин: admin   Пароль: ' + pw + '\nСмените пароль: node server.js set-password admin НОВЫЙ_ПАРОЛЬ\n');
}

const hs = t => crypto.createHash('sha256').update(String(t)).digest('hex'); // в базе лежит только хэш токена
const fails = new Map(), regHits = new Map(), putHits = new Map();
const ip = req => { const tp = process.env.TRUST_PROXY; if (tp === 'cloudflare') return String(req.headers['cf-connecting-ip'] || req.socket.remoteAddress); if (tp) { const l = String(req.headers['x-forwarded-for'] || '').split(',').map(x => x.trim()).filter(Boolean); return l[l.length - 1] || req.socket.remoteAddress; } return req.socket.remoteAddress; };
const cookie = req => Object.fromEntries(String(req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(a => a[0]));
const who = req => { const s = sql.prepare('SELECT login, exp FROM sessions WHERE id = ?').get(hs(cookie(req).sid)); return s && s.exp > Date.now() ? s.login : null; };
const send = (res, code, obj, extra = {}) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra }); res.end(JSON.stringify(obj)); };
const body = (req, max = 200000) => new Promise((ok, no) => { let b = '', n = 0; req.on('data', c => { n += c.length; if (n > max) { no(new Error('big')); req.destroy(); } else b += c; }); req.on('end', () => { try { ok(b ? JSON.parse(b) : {}); } catch { no(new Error('json')); } }); });
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, max);

const url = v => { try { const u = new URL(String(v || '').trim()); return /^https?:$/.test(u.protocol) ? u.href.slice(0, 300) : ''; } catch { return ''; } };
function cleanSite(s) {
  const c = s.cfg || {}, pick = (v, list, d) => list.includes(v) ? v : d;
  const out = {
    news: (Array.isArray(s.news) ? s.news : []).slice(0, 50).map(n => ({ title: str(n.title, 120), text: str(n.text, 600) })),
    prizes: (Array.isArray(s.prizes) ? s.prizes : []).slice(0, 20).map(n => ({ place: str(n.place, 60), sum: str(n.sum, 60) })),
    schedule: (Array.isArray(s.schedule) ? s.schedule : []).slice(0, 30).map(n => ({ stage: str(n.stage, 100), when: str(n.when, 100) })),
    teams: (Array.isArray(s.teams) ? s.teams : []).slice(0, 64).map(t => str(t, 60)).filter(Boolean),
    cfg: { size: pick(+c.size, [8, 16, 32, 64], 64), format: pick(c.format, ['single', 'roundrobin'], 'single'), bo: pick(+c.bo, [1, 3, 5], 1), boSemi: pick(+c.boSemi, [1, 3, 5], 1), boFinal: pick(+c.boFinal, [1, 3, 5], 1) },
    streams: (Array.isArray(s.streams) ? s.streams : []).slice(0, 20).map(n => ({ title: str(n.title, 100), url: url(n.url), when: str(n.when, 100) })),
    partners: (Array.isArray(s.partners) ? s.partners : []).slice(0, 30).map(n => ({ name: str(n.name, 60), url: url(n.url) })),
    packages: (Array.isArray(s.packages) ? s.packages : []).slice(0, 6).map(n => ({ name: str(n.name, 60), price: str(n.price, 40), perks: str(n.perks, 400) })),
    donateUrl: url(s.donateUrl),
    regOpen: s.regOpen !== false, regMax: Math.min(100000, Math.max(0, parseInt(s.regMax, 10) || 0)), regUntil: isFinite(Date.parse(s.regUntil)) ? new Date(s.regUntil).toISOString() : '',
    regAuto: true, checkinUntil: '', // только автоматический приём; ручной режим и check-in отключены
    maps: (Array.isArray(s.maps) ? s.maps : []).slice(0, 30).map(n => ({ name: str(n.name, 40), note: str(n.note, 80) })).filter(n => n.name), mapsNote: str(s.mapsNote, 200),
    privOrg: str(s.privOrg, 120), privContact: str(s.privContact, 120), privRetention: str(s.privRetention, 300),
    results: {}
  };
  Object.entries(s.results && typeof s.results === 'object' ? s.results : {}).slice(0, 700).forEach(([k, v]) => {
    if (!/^(rr:)?\d{1,2}-\d{1,3}$/.test(k)) return;
    const w = v && typeof v === 'object' ? v.w : v; if (w !== 0 && w !== 1) return;
    const sc = v && typeof v === 'object' ? str(v.sc, 12) : ''; out.results[k] = sc ? { w, sc } : { w };
  });
  return out;
}

function migrateJson() { // перенос старых JSON-файлов (v1.0) в базу, один раз
  const oldData = path.join(DIR, 'data.json'), oldUsers = path.join(DIR, 'admins.json');
  if (fs.existsSync(oldUsers)) {
    tx(() => Object.entries(readJson(oldUsers, {})).forEach(([l, v]) => v && v.salt && v.hash && sql.prepare('INSERT OR IGNORE INTO admins (login, salt, hash) VALUES (?, ?, ?)').run(l.toLowerCase(), v.salt, v.hash)));
    fs.renameSync(oldUsers, oldUsers + '.migrated'); console.log('Администраторы перенесены из admins.json в базу.');
  }
  if (fs.existsSync(oldData)) {
    const d = readJson(oldData, null); let n = 0;
    if (d) tx(() => {
      if (d.site && !getSite()) putSite(cleanSite(d.site));
      (d.regs || []).forEach(r => { const t = str(r.team, 40); if (!t) return;
        n += sql.prepare('INSERT OR IGNORE INTO regs (id, at, status, confirmed, confirmed_at, ctoken, team, team_norm, captain, contact, roster) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .run(String(r.id || crypto.randomUUID()), +r.at || Date.now(), ['new', 'accepted', 'rejected'].includes(r.status) ? r.status : 'new', r.confirmed ? 1 : 0, r.confirmedAt || null, String(r.ctoken || crypto.randomBytes(16).toString('hex')), t, norm(t), str(r.captain, 60), str(r.contact, 80), str(r.roster, 600)).changes; });
    });
    fs.renameSync(oldData, oldData + '.migrated'); console.log('Данные перенесены из data.json в базу (заявок: ' + n + '). Старый файл сохранён как data.json.migrated.');
  }
}
migrateJson();
if (!sql.prepare('SELECT COUNT(*) AS n FROM admins').get().n) { // первый запуск
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  setPassword('admin', pw); console.log('\nСоздан администратор.  Логин: admin   Пароль: ' + pw + '\nСмените пароль: node server.js set-password admin НОВЫЙ_ПАРОЛЬ\n');
}

/* ===== Защита от спама и атак ===== */
const SECRET = crypto.randomBytes(32), usedNonce = new Map(), heat = [], strikes = new Map();
const rlAll = new Map(), rlApi = new Map(), rlChal = new Map(), regHour = new Map(), regDay = new Map(), regAll = new Map(), confHit = new Map(), ufail = new Map();
const banned = new Map(sql.prepare('SELECT ip, until FROM bans WHERE until > ?').all(Date.now()).map(r => [r.ip, r.until]));
const exempt = a => !process.env.PROTECT_LOOPBACK && /^(::1|127\.|::ffff:127\.)/.test(String(a)); // сервер за прокси без TRUST_PROXY: не блокируем «всех сразу»
const hit = (map, key, windowMs, max) => { const now = Date.now(), a = (map.get(key) || []).filter(t => now - t < windowMs); if (a.length >= max) { map.set(key, a); return false; } a.push(now); map.set(key, a); return true; };
const hitIp = (map, a, w, max) => exempt(a) || hit(map, a, w, max);
const isBanned = a => { // «node server.js unban IP» действует сразу, без перезапуска
  if (exempt(a)) return false; const u = banned.get(a); if (!u || u <= Date.now()) return false;
  if (!sql.prepare('SELECT 1 FROM bans WHERE ip = ?').get(a)) { banned.delete(a); return false; } return true;
};
function ban(a, why) {
  const prev = sql.prepare('SELECT until FROM bans WHERE ip = ?').get(a), now = Date.now(), until = now + (prev && now - prev.until < 86400000 ? 86400000 : 3600000);
  banned.set(a, until); strikes.delete(a);
  sql.prepare('INSERT INTO bans (ip, until, reason, at) VALUES (?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET until = excluded.until, reason = excluded.reason, at = excluded.at').run(a, until, String(why).slice(0, 40), now);
  console.log('Блокировка IP ' + a + ' до ' + new Date(until).toLocaleString('ru-RU') + ': ' + why);
}
function strike(a, w, why) { // штрафные очки за подозрительное поведение; 1 очко «сгорает» за минуту; 10 очков — бан
  if (exempt(a)) return; const now = Date.now(), e = strikes.get(a) || { s: 0, t: now };
  e.s = Math.max(0, e.s - (now - e.t) / 60000) + w; e.t = now; strikes.set(a, e); if (e.s >= 10) ban(a, why);
}
function regState(site) {
  const st = site || {}, n = sql.prepare("SELECT COUNT(*) AS n FROM regs WHERE status != 'rejected'").get().n, max = +st.regMax || 0, until = st.regUntil ? Date.parse(st.regUntil) : 0;
  const size = +((st.cfg && st.cfg.size) || 64), inBracket = Array.isArray(st.teams) ? st.teams.length : 0;
  const slotsLeft = Math.max(0, size - inBracket);
  let open = true, reason = '';
  if (st.regOpen === false) { open = false; reason = 'closed'; }
  else if (until && Date.now() > until) { open = false; reason = 'expired'; }
  else if (slotsLeft <= 0) { open = false; reason = 'full'; } // сетка заполнена — заявки больше не принимаются
  else if (max && n >= max) { open = false; reason = 'cap'; }
  // left = свободные места в сетке (и с учётом лимита заявок, если он задан)
  const leftByCap = max ? Math.max(0, max - n) : null;
  const left = leftByCap == null ? slotsLeft : Math.min(slotsLeft, leftByCap);
  return { open, reason, left, slots: slotsLeft, size, until: st.regUntil || '', checkin: st.checkinUntil || '' };
}
// Задача для браузера (proof-of-work): стоит боту CPU-времени, обычному человеку — доли секунды. Под атакой сложность растёт.
const currentBits = () => { const now = Date.now(); while (heat.length && now - heat[0] > 300000) heat.shift(); return 16 + Math.min(4, Math.floor(Math.log2(1 + heat.length / 40))); };
const sign = p => crypto.createHmac('sha256', SECRET).update(p).digest('hex').slice(0, 32);
function verifyPow(pow) {
  const bad = (err, w) => ({ err, w });
  if (!pow || typeof pow.token !== 'string' || !/^\d{1,10}$/.test(String(pow.counter))) return bad('Не пройдена проверка защиты. Обновите страницу.', 3);
  const [nonce, bits, ts, sg] = pow.token.split('.');
  if (!/^[a-f0-9]{16}$/.test(nonce || '') || !/^\d{2}$/.test(bits || '') || !/^\d{10,15}$/.test(ts || '') || !/^[a-f0-9]{32}$/.test(sg || '')) return bad('Не пройдена проверка защиты. Обновите страницу.', 3);
  if (!crypto.timingSafeEqual(Buffer.from(sign(nonce + '.' + bits + '.' + ts)), Buffer.from(sg))) return bad('Не пройдена проверка защиты. Обновите страницу.', 3);
  const age = Date.now() - +ts;
  if (age < 2800) return bad('Слишком быстро. Подождите пару секунд и отправьте ещё раз.', 1);
  if (age > 1800000 || usedNonce.has(nonce)) return bad('Проверка устарела. Нажмите «Отправить» ещё раз.', 1);
  const h = crypto.createHash('sha256').update(nonce + ':' + pow.counter).digest(); let z = 0;
  for (const byte of h) { if (byte === 0) { z += 8; continue; } z += Math.clz32(byte) - 24; break; }
  if (z < +bits) return bad('Проверка не пройдена. Нажмите «Отправить» ещё раз.', 3);
  usedNonce.set(nonce, Date.now() + 1800000); return null;
}
const sameOrigin = req => { // запрос на изменение должен идти с самого сайта
  if (req.headers['sec-fetch-site'] === 'cross-site') return false;
  const o = req.headers.origin; if (!o) return true;
  try { const h = new URL(o).host; return h === req.headers.host || (!!process.env.TRUST_PROXY && h === req.headers['x-forwarded-host']) || String(process.env.ALLOWED_ORIGIN || '').split(',').some(x => { try { return new URL(x.trim()).host === h; } catch { return false; } }); } catch { return false; }
};
const URLISH = /(https?:\/\/|www\.|t\.me\/|discord\.gg)/i;
setInterval(() => {
  const now = Date.now();
  for (const m of [rlAll, rlApi, rlChal, regHour, regDay, regAll, confHit, ufail, fails, putHits]) for (const [k, a] of m) { const last = Array.isArray(a) ? a[a.length - 1] : (a.until || 0); if (!last || now - last > 86400000) m.delete(k); }
  for (const [k, v] of usedNonce) if (v < now) usedNonce.delete(k);
  for (const [k, e] of strikes) if (now - e.t > 3600000) strikes.delete(k);
  for (const [k, u] of banned) if (u < now) banned.delete(k);
  sql.prepare('DELETE FROM sessions WHERE exp < ?').run(now); sql.prepare('DELETE FROM bans WHERE until < ?').run(now - 86400000);
}, 300000).unref();
let proxyWarned = false;

/* ===== Автоматический приём: места в сетке, очередь, подтверждение участия ===== */
function defaultSite() { try { const m = fs.readFileSync(PAGE, 'utf8').match(/<script type="application\/json" id="siteData">([\s\S]*?)<\/script>/); return cleanSite(JSON.parse(m[1])); } catch { return cleanSite({}); } }
const siteNow = () => getSite() || defaultSite();
const teamIn = (site, name) => site.teams.some(t => norm(t) === norm(name));
const isLate = site => !!site.checkinUntil && Date.now() > Date.parse(site.checkinUntil);
function setAccepted(site, r) {
  // В автоматическом режиме и после срока check-in сразу подтверждаем — админам не нужно писать капитану
  const auto = (site.regAuto !== false || isLate(site)) ? 1 : 0;
  sql.prepare('UPDATE regs SET status = ?, confirmed = CASE WHEN ? = 1 THEN 1 ELSE confirmed END, confirmed_at = CASE WHEN ? = 1 THEN COALESCE(confirmed_at, ?) ELSE confirmed_at END WHERE id = ?').run('accepted', auto, auto, Date.now(), r.id);
  if (!teamIn(site, r.team)) site.teams.push(r.team);
}
function fillSlots() { // свободное место → следующая команда из очереди (в порядке подачи)
  const site = siteNow(); if (site.regAuto === false) return; let changed = false;
  while (site.teams.length < site.cfg.size) {
    const r = sql.prepare("SELECT * FROM regs WHERE status = 'new' ORDER BY at ASC LIMIT 1").get(); if (!r) break;
    setAccepted(site, r); changed = true;
  }
  if (changed) putSite(site);
}
function dropTeam(name) { const site = siteNow(), n = site.teams.length; site.teams = site.teams.filter(t => norm(t) !== norm(name)); if (site.teams.length !== n) putSite(site); }
function checkinSweep() { // срок подтверждения вышел: кто не подтвердил — освобождает место
  const site = getSite(); if (!site || !site.checkinUntil || Date.now() < Date.parse(site.checkinUntil)) return;
  const rows = sql.prepare("SELECT * FROM regs WHERE status = 'accepted' AND confirmed = 0").all(); if (!rows.length) return;
  tx(() => { rows.forEach(r => sql.prepare("UPDATE regs SET status = 'rejected' WHERE id = ?").run(r.id)); site.teams = site.teams.filter(t => !rows.some(r => r.team_norm === norm(t))); putSite(site); });
  console.log('Не подтвердили участие и удалены из сетки: ' + rows.map(r => r.team).join(', ')); fillSlots();
}
setInterval(() => { try { checkinSweep(); } catch (e) { console.error(e.message); } }, +process.env.SWEEP_MS || 60000).unref();

const esc = x => String(x == null ? '' : x).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const PRIVACY_DATE = '7 ноября 2026';
function privacyPage() {
  const s = siteNow(), org = esc(s.privOrg || 'Организатор турнира MAJOR CSS'), contact = esc(s.privContact || 'Telegram: @Aleksus_06'),
    keep = esc(s.privRetention || 'Данные хранятся до завершения турнира. После завершения организаторы удаляют заявки; удалить данные раньше можно по запросу.');
  return `<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark">
<title>Политика конфиденциальности — MAJOR CSS</title><meta name="robots" content="index,follow">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;800&display=swap">
<style>:root{color-scheme:dark}body{margin:0;background:#08090b;color:#f4f4f5;font-family:Manrope,Arial,sans-serif;line-height:1.7}
main{max-width:760px;margin:0 auto;padding:48px 20px 80px}a{color:#ff4655}h1{font-size:clamp(30px,6vw,44px);line-height:1.15;margin:.4em 0}
h2{font-size:20px;margin:2em 0 .4em}p,li{color:#d2d3d7;font-size:16px}ul{padding-left:1.2em}li{margin:.4em 0}.top{font-size:14px;color:#a3a5ad}
.box{border-left:3px solid #e32636;background:#111317;padding:14px 18px;margin:18px 0}</style></head><body><main>
<a href="/">← На главную</a><h1>Политика конфиденциальности</h1><p class="top">Редакция от ${PRIVACY_DATE}</p>
<p>Здесь простыми словами написано, какие данные собирает сайт турнира MAJOR CSS (Counter Shot: Source), зачем, кто их видит и как их удалить.</p>
<div class="box"><strong>Коротко.</strong> Мы собираем только данные из заявки. Публично показывается только название команды. Имя капитана, контакт и состав видят лишь администраторы. Рекламы и счётчиков посещаемости на сайте нет. Данные можно удалить по запросу.</div>
<h2>1. Кто отвечает за данные</h2><p>Оператор данных: ${org}.<br>По любым вопросам о данных пишите: ${contact}.</p>
<h2>2. Какие данные мы получаем</h2><ul>
<li><b>Из заявки на участие:</b> название команды, имя или ник капитана, ники игроков из состава (если указали) и при желании контакт для связи.</li>
<li><b>Технические данные:</b> IP-адрес и сведения о запросе обрабатываются сервером, чтобы защитить форму от спама и атак. Обычно они хранятся только в оперативной памяти и пропадают при перезапуске сервера. Если адрес заблокирован за нарушения, адрес и причина записываются в базу на срок блокировки и ещё до суток после него.</li>
<li><b>Cookie:</b> сайт не использует рекламные и аналитические cookie. Служебный cookie выдаётся только администраторам после входа, посетителям — нет.</li></ul>
<h2>3. Зачем мы это делаем</h2><p>Чтобы принять заявку, связаться с капитаном, подтвердить участие, составить турнирную сетку и защитить сайт от злоупотреблений. Для других целей данные не используются.</p>
<h2>4. Основание и согласие</h2><p>Мы обрабатываем данные на основании вашего согласия, которое вы даёте, отметив галочку в форме заявки. Согласие можно отозвать в любой момент, написав по контакту выше. Если вы указываете в составе других людей, вы подтверждаете, что они знают об этом и не возражают. Время получения согласия сохраняется вместе с заявкой.</p>
<h2>5. Кто видит данные</h2><ul>
<li><b>Публично</b> показывается только название команды (после принятия — в списке участников и сетке) и результаты матчей.</li>
<li><b>Не публикуются:</b> имя капитана, контакт, состав команды. Их видят только администраторы сайта.</li></ul>
<h2>6. Передача третьим лицам</h2><p>Мы не продаём данные и не передаём их третьим лицам, кроме случаев, когда этого требует закон. Технически данные хранятся на сервере хостинг-провайдера, где работает сайт.</p>
<p>Сторонние ресурсы: страница загружает шрифты с серверов Google Fonts, при этом Google получает ваш IP-адрес и сведения о браузере по собственным правилам. Ссылки на Telegram, трансляции и партнёров ведут на чужие сайты со своими правилами.</p>
<h2>7. Сколько хранятся данные</h2><p>${keep}</p>
<h2>8. Ваши права</h2><p>Вы можете узнать, какие данные о вас хранятся, потребовать исправить или удалить их, а также отозвать согласие. Напишите по контакту выше: администратор удалит заявку в панели сайта, и она исчезнет из базы заявок. Если организаторы делают резервные копии, в них данные могут оставаться до удаления самой копии.</p>
<h2>9. Как мы защищаем данные</h2><p>Доступ к заявкам есть только у администраторов. Пароли администраторов хранятся в виде хэшей. Форма заявки защищена от автоматических отправок и массового спама.</p>
<h2>10. Изменения</h2><p>Если политика изменится, мы обновим эту страницу и дату редакции.</p>
<p class="top" style="margin-top:3em"><a href="/">← На главную</a></p></main></body></html>`;
}
const origin = req => (process.env.SECURE || (process.env.TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https') ? 'https' : 'http') + '://' + (/^[a-z0-9.\-]+(:\d+)?$/i.test(req.headers.host || '') ? req.headers.host : 'localhost');
const sendText = (req, res, code, type, text, extra = {}) => {
  const buf = Buffer.from(text), gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '') && buf.length > 1024;
  res.writeHead(code, { 'Content-Type': type, Vary: 'Accept-Encoding', ...(gz ? { 'Content-Encoding': 'gzip' } : {}), ...extra }); res.end(gz ? require('zlib').gzipSync(buf) : buf);
};
const FAVICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><path d="M0 0h32v24l-8 8H0z" fill="#e32636"/><text x="16" y="23" font-size="20" font-weight="900" text-anchor="middle" fill="#fff" font-family="Arial">M</text></svg>`;

const srv = http.createServer(async (req, res) => {
  let u; try { u = new URL(req.url, 'http://x'); } catch { res.writeHead(400); return res.end(); }
  const p = u.pathname, m = req.method, addr = ip(req);
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (process.env.SECURE) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  if (!process.env.TRUST_PROXY && !proxyWarned && exempt(addr) && (req.headers['x-forwarded-for'] || req.headers['cf-connecting-ip'])) { proxyWarned = true; console.warn('ВНИМАНИЕ: запросы идут через прокси, но TRUST_PROXY не задан — защита по IP не работает. Запустите с TRUST_PROXY=1 (nginx) или TRUST_PROXY=cloudflare.'); }
  if (isBanned(addr)) { res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Доступ закрыт.'); }
  if (!hitIp(rlAll, addr, 60000, 300)) { strike(addr, 1, 'flood'); res.writeHead(429, { 'Retry-After': '30' }); return res.end(); }
  try {
    if (m === 'GET' && (p === '/' || p === '/index.html')) return sendText(req, res, 200, 'text/html; charset=utf-8', fs.readFileSync(PAGE, 'utf8').split('__ORIGIN__').join(origin(req)), { 'Cache-Control': 'no-cache' });
    if (m === 'GET' && p === '/privacy') return sendText(req, res, 200, 'text/html; charset=utf-8', privacyPage(), { 'Cache-Control': 'no-cache' });
    if (m === 'GET' && p === '/og-image.png') { let img; try { img = fs.readFileSync(path.join(DIR, 'og-image.png')); } catch { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' }); return res.end(img); }
    if (m === 'GET' && p === '/robots.txt') return sendText(req, res, 200, 'text/plain; charset=utf-8', 'User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: ' + origin(req) + '/sitemap.xml\n');
    if (m === 'GET' && p === '/sitemap.xml') return sendText(req, res, 200, 'application/xml; charset=utf-8', '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + origin(req) + '/</loc></url><url><loc>' + origin(req) + '/privacy</loc></url></urlset>\n');
    if (m === 'GET' && (p === '/favicon.svg' || p === '/favicon.ico')) return sendText(req, res, 200, 'image/svg+xml', FAVICON, { 'Cache-Control': 'public, max-age=86400' });
    if (!p.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }
    if (m !== 'GET' && !String(req.headers['content-type'] || '').includes('application/json')) return send(res, 415, { error: 'Нужен JSON' });
    const user = who(req), key = p.slice(5);
    if (!hitIp(rlApi, addr, 60000, 120)) { strike(addr, 1, 'api-flood'); return send(res, 429, { error: 'Слишком много запросов. Подождите минуту.' }, { 'Retry-After': '60' }); }
    if (m !== 'GET' && !sameOrigin(req)) { strike(addr, 2, 'origin'); return send(res, 403, { error: 'Запрос отклонён.' }); }

    if (key === 'ping') return send(res, 200, { ok: true });
    if (key === 'me') return send(res, 200, { user });
    if (key === 'data' && m === 'GET') return send(res, 200, { site: getSite(), reg: regState(getSite()) });

    if (key === 'login' && m === 'POST') {
      const a = ip(req), f = fails.get(a) || { n: 0, until: 0 };
      if (f.until > Date.now()) return send(res, 429, { error: 'Слишком много попыток. Подождите несколько минут.' });
      const b = await body(req), login = str(b.user, 40).toLowerCase(), acc = sql.prepare('SELECT salt, hash FROM admins WHERE login = ?').get(login);
      if ((ufail.get(login) || []).filter(t => Date.now() - t < 900000).length >= 20) return send(res, 429, { error: 'Слишком много неверных попыток для этой учётной записи. Подождите 15 минут.' });
      const ok = acc ? crypto.timingSafeEqual(Buffer.from(hashPw(String(b.pass || ''), acc.salt), 'hex'), Buffer.from(acc.hash, 'hex')) : (hashPw(String(b.pass || ''), '00000000000000000000000000000000'), false);
      if (!ok) { const ul = ufail.get(login) || []; ul.push(Date.now()); ufail.set(login, ul.filter(t => Date.now() - t < 900000)); strike(addr, 1, 'login'); f.n++; if (f.n >= 5) { f.until = Date.now() + 300000; f.n = 0; } fails.set(a, f); return send(res, 401, { error: 'Неверный логин или пароль.' }); }
      fails.delete(a); const sid = crypto.randomBytes(32).toString('hex'); sql.prepare('DELETE FROM sessions WHERE exp < ?').run(Date.now()); sql.prepare('INSERT INTO sessions (id, login, exp) VALUES (?, ?, ?)').run(hs(sid), login, Date.now() + 43200000);
      return send(res, 200, { ok: true }, { 'Set-Cookie': `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${process.env.SECURE ? '; Secure' : ''}` });
    }
    if (key === 'logout' && m === 'POST') { sql.prepare('DELETE FROM sessions WHERE id = ?').run(hs(cookie(req).sid)); return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' }); }

    if (key === 'challenge' && m === 'GET') {
      if (!hitIp(rlChal, addr, 60000, 12)) { strike(addr, 1, 'challenge'); return send(res, 429, { error: 'Слишком часто. Подождите минуту.' }); }
      heat.push(Date.now()); const nonce = crypto.randomBytes(8).toString('hex'), bits = currentBits(), base = nonce + '.' + bits + '.' + Date.now();
      return send(res, 200, { ok: true, token: base + '.' + sign(base), nonce, bits });
    }

    if (key === 'register' && m === 'POST') {
      const st = regState(getSite());
      if (!st.open) return send(res, 403, { error: { closed: 'Приём заявок закрыт.', full: 'Приём заявок закрыт: сетка заполнена, свободных мест нет.', cap: 'Приём заявок закрыт: набрано максимальное число заявок.', expired: 'Приём заявок завершён.' }[st.reason] || 'Приём заявок закрыт.' });
      const b = await body(req, 12000);
      if (b.web) { strike(addr, 10, 'honeypot'); return send(res, 200, { ok: true }); } // бота «принимаем» молча и блокируем
      const pw = verifyPow(b.pow); if (pw) { strike(addr, pw.w, 'pow'); return send(res, 400, { error: pw.err }); }
      const r = { id: crypto.randomUUID(), at: Date.now(), status: 'new', confirmed: false, ctoken: crypto.randomBytes(16).toString('hex'), team: str(b.team, 40), captain: str(b.captain, 40), contact: str(b.contact, 60), roster: str(b.roster, 600) };
      const rosterLines = r.roster.split('\n').map(x => x.trim()).filter(Boolean);
      const fail = msg => { strike(addr, 1, 'invalid'); return send(res, 400, { error: msg }); };
      if (!/^[\p{L}\p{N} ._\-\[\]()!&'+#|]{2,40}$/u.test(r.team)) return fail('Название команды: 2–40 символов, буквы, цифры и простые знаки.');
      if (!/^[\p{L}\p{N} ._\-']{2,40}$/u.test(r.captain)) return fail('Имя капитана: 2–40 символов, только буквы, цифры и простые знаки.');
      if (r.contact && !/^[@\p{L}\p{N}._\-#:+ ]{3,60}$/u.test(r.contact)) return fail('Контакт (если указываете): 3–60 символов, без ссылок.');
      if (rosterLines.length > 12 || rosterLines.some(x => x.length > 40)) return fail('Состав: не больше 12 игроков, по одному в строке, до 40 символов.');
      if (URLISH.test([r.team, r.captain, r.contact, r.roster].join(' '))) return fail('Ссылки в заявке не допускаются.');
      if (b.consent !== true) return send(res, 400, { error: 'Нужно согласие на обработку данных.' });
      const site = getSite();
      if (sql.prepare("SELECT 1 FROM regs WHERE team_norm = ? AND status != 'rejected'").get(norm(r.team)) || ((site && site.teams) || []).some(t => norm(t) === norm(r.team))) return send(res, 409, { error: 'Команда с таким названием уже подала заявку.' });
      if (r.contact && sql.prepare("SELECT COUNT(*) AS n FROM regs WHERE lower(contact) = ? AND status != 'rejected'").get(r.contact.toLowerCase()).n >= 2) return send(res, 409, { error: 'С этим контактом уже подано максимальное число заявок.' });
      if (!hitIp(regHour, addr, 3600000, 3) || !hitIp(regDay, addr, 86400000, 8)) { strike(addr, 2, 'reg-rate'); return send(res, 429, { error: 'Слишком много заявок с вашего адреса. Попробуйте позже.' }); }
      if (!hit(regAll, 'all', 3600000, 300)) return send(res, 429, { error: 'Сейчас слишком много заявок. Попробуйте через час.' });
      if (sql.prepare('SELECT COUNT(*) AS n FROM regs').get().n >= 100000) return send(res, 503, { error: 'Приём заявок временно закрыт.' });
      // Автоматический режим: заявка сразу подтверждена — админам не нужно писать капитану
      const autoConfirm = 1;
      sql.prepare('INSERT INTO regs (id, at, status, confirmed, confirmed_at, ctoken, team, team_norm, captain, contact, roster, consent_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(r.id, r.at, r.status, autoConfirm, r.at, r.ctoken, r.team, norm(r.team), r.captain, r.contact, r.roster, r.at);
      fillSlots();
      const row = sql.prepare('SELECT status, confirmed FROM regs WHERE id = ?').get(r.id);
      // Очереди нет: если места не оказалось — удаляем заявку и отвечаем, что сетка заполнена
      if (row.status !== 'accepted') {
        sql.prepare('DELETE FROM regs WHERE id = ?').run(r.id);
        return send(res, 403, { error: 'Приём заявок закрыт: сетка заполнена, свободных мест нет.' });
      }
      return send(res, 200, { ok: true, status: row.status, confirmed: !!row.confirmed, ctoken: r.ctoken });
    }

    if (key === 'confirm') {
      const now = Date.now();
      if (!hitIp(confHit, addr, 3600000, 30)) { strike(addr, 1, 'confirm'); return send(res, 429, { error: 'Слишком много попыток. Попробуйте позже.' }); }

      const token = m === 'GET' ? u.searchParams.get('token') : (await body(req)).token;
      const row = /^[a-f0-9]{32}$/.test(String(token || '')) && sql.prepare('SELECT * FROM regs WHERE ctoken = ?').get(token), r = row && regRow(row);
      if (!r) { strike(addr, 1, 'confirm-bad'); return send(res, 404, { error: 'Ссылка недействительна или устарела.' }); }
      if (m === 'GET') return send(res, 200, { ok: true, team: r.team, confirmed: !!r.confirmed });
      if (m === 'POST') { if (!r.confirmed) { sql.prepare('UPDATE regs SET confirmed = 1, confirmed_at = ? WHERE id = ?').run(now, r.id); } return send(res, 200, { ok: true, team: r.team }); }
      return send(res, 405, { error: 'Метод не поддерживается.' });
    }
    if (!user) return send(res, 401, { error: 'Нужен вход администратора.' });
    if (key === 'data' && m === 'PUT') { const now = Date.now(), hh = (putHits.get(user) || []).filter(t => now - t < 60000); if (hh.length >= 30) return send(res, 429, { error: 'Слишком часто. Подождите минуту.' }); hh.push(now); putHits.set(user, hh); putSite(cleanSite(await body(req))); fillSlots(); return send(res, 200, { ok: true }); }
    if (key === 'backup' && m === 'GET') return send(res, 200, { site: getSite(), regs: allRegs() }, { 'Content-Disposition': 'attachment; filename="major-css-backup.json"' });
    if (key === 'registrations' && m === 'GET') return send(res, 200, { ok: true, items: allRegs() });
    if (key === 'registrations' && m === 'DELETE') { sql.prepare('DELETE FROM regs').run(); return send(res, 200, { ok: true }); } // удалить все заявки (после турнира)
    const mm = key.match(/^registrations\/([\w-]+)$/);
    if (mm) {
      const id = mm[1], row = sql.prepare('SELECT * FROM regs WHERE id = ?').get(id); if (!row) return send(res, 404, { error: 'Заявка не найдена.' });
      const site = siteNow();
      if (m === 'DELETE') { sql.prepare('DELETE FROM regs WHERE id = ?').run(id); if (row.status === 'accepted') dropTeam(row.team); fillSlots(); }
      else if (m === 'PATCH') {
        const st = (await body(req)).status; if (!['new', 'accepted', 'rejected'].includes(st)) return send(res, 400, { error: 'Неверный статус.' });
        if (st === 'accepted') { if (!teamIn(site, row.team) && site.teams.length >= site.cfg.size) return send(res, 409, { error: 'В сетке нет свободных мест (' + site.cfg.size + ').' }); setAccepted(site, row); putSite(site); }
        else { sql.prepare('UPDATE regs SET status = ? WHERE id = ?').run(st, id); if (row.status === 'accepted') dropTeam(row.team); fillSlots(); }
      } else return send(res, 405, { error: 'Метод не поддерживается.' });
      return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'Не найдено.' });
  } catch (e) { if (!res.headersSent) send(res, 400, { error: 'Некорректный запрос.' }); else res.end(); }
});
srv.headersTimeout = 10000; srv.requestTimeout = 15000; srv.keepAliveTimeout = 5000; srv.maxHeadersCount = 50; srv.maxConnections = 2000; // против «медленных» атак
srv.on('error', e => { console.error('Ошибка сервера:', e.message); process.exit(1); }).listen(PORT, () => console.log('MAJOR CSS v1.3 → http://localhost:' + PORT));
