const express = require('express');
const path = require('node:path');
const crypto = require('node:crypto');
const QRCode = require('qrcode');
const ExcelJS = require('exceljs');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Длительность одного "окна" действия QR-кода охранника
const WINDOW_SECONDS = 60;
const GUARD_SECRET = db.getOrCreateGuardSecret();

// Единственные аккаунты охраны и администратора — создаются один раз при
// первом запуске. Логин/пароль можно переопределить переменными окружения
// перед первым стартом (после создания аккаунта они уже не влияют).
const GUARD_LOGIN = process.env.GUARD_LOGIN || 'guard';
const GUARD_PASSWORD = process.env.GUARD_PASSWORD || 'guard123';
const guardAccount = db.getOrCreateSingletonAccount('guard', 'Охрана', GUARD_LOGIN, GUARD_PASSWORD);
console.log(`Аккаунт охраны: логин "${guardAccount.login}"` +
  (process.env.GUARD_PASSWORD ? '' : ` (пароль по умолчанию "${GUARD_PASSWORD}" — задайте GUARD_PASSWORD, чтобы изменить)`));

const ADMIN_LOGIN = process.env.ADMIN_LOGIN || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const adminAccount = db.getOrCreateSingletonAccount('admin', 'Администратор', ADMIN_LOGIN, ADMIN_PASSWORD);
console.log(`Аккаунт администратора: логин "${adminAccount.login}"` +
  (process.env.ADMIN_PASSWORD ? '' : ` (пароль по умолчанию "${ADMIN_PASSWORD}" — задайте ADMIN_PASSWORD, чтобы изменить)`));

app.use(express.json());

// --- Простейшие сессии на подписанных cookie (без внешних зависимостей) ---

const SESSION_SECRET = db.getOrCreateSessionSecret();
const sessions = new Map(); // sid -> { id, role, full_name }
const SID_COOKIE = 'sid';

function signSid(sid) {
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(sid).digest('hex').slice(0, 16);
  return `${sid}.${sig}`;
}

function parseSignedSid(signed) {
  if (!signed) return null;
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const sid = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(sid).digest('hex').slice(0, 16);
  const bufA = Buffer.from(sig);
  const bufB = Buffer.from(expectedSig);
  if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) return null;
  return sid;
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    out[key] = decodeURIComponent(val);
  }
  return out;
}

function createSession(user) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { id: user.id, role: user.role, full_name: user.full_name });
  return sid;
}

function destroySession(sid) {
  sessions.delete(sid);
}

// Подтягиваем текущего пользователя (если есть валидная cookie) в req.user
app.use((req, res, next) => {
  const cookies = parseCookies(req);
  const sid = parseSignedSid(cookies[SID_COOKIE]);
  if (sid && sessions.has(sid)) {
    req.sid = sid;
    req.user = sessions.get(sid);
  }
  next();
});

function requireAuth(role) {
  const allowed = role ? (Array.isArray(role) ? role : [role]) : null;
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Требуется авторизация' });
    if (allowed && !allowed.includes(req.user.role)) return res.status(403).json({ error: 'Недостаточно прав' });
    next();
  };
}

app.use(express.static(path.join(__dirname, 'public')));

function currentWindow() {
  return Math.floor(Date.now() / (WINDOW_SECONDS * 1000));
}

function computeGuardToken(window) {
  return crypto
    .createHmac('sha256', GUARD_SECRET)
    .update(String(window))
    .digest('hex')
    .slice(0, 8)
    .toUpperCase();
}

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}



// --- Аутентификация ---

app.post('/api/auth/login', (req, res) => {
  const { login, password } = req.body || {};
  const user = login ? db.getUserByLogin(login.trim()) : null;
  if (!user || !db.verifyPassword(password || '', user.password_salt, user.password_hash)) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  if (!user.active) {
    return res.status(403).json({ error: 'Аккаунт деактивирован' });
  }
  const sid = createSession(user);
  res.setHeader('Set-Cookie', `${SID_COOKIE}=${signSid(sid)}; HttpOnly; Path=/; SameSite=Lax`);
  res.json({ id: user.id, full_name: user.full_name, role: user.role });
});

app.post('/api/auth/logout', (req, res) => {
  if (req.sid) destroySession(req.sid);
  res.setHeader('Set-Cookie', `${SID_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth(), (req, res) => {
  res.json(req.user);
});

app.post('/api/auth/change-password', requireAuth(), (req, res) => {
  const { current_password, new_password } = req.body || {};
  const user = db.getUserById(req.user.id);
  if (!user) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  if (!current_password || !db.verifyPassword(current_password, user.password_salt, user.password_hash)) {
    return res.status(400).json({ error: 'Текущий пароль указан неверно' });
  }
  if (!new_password || new_password.length < 6) {
    return res.status(400).json({ error: 'Новый пароль должен быть не короче 6 символов' });
  }
  db.updateUserPassword(user.id, new_password);
  res.json({ ok: true });
});

// --- Сотрудники (только для охраны/админа) ---

app.get('/api/employees', requireAuth('admin'), (req, res) => {
  res.json(db.listEmployees());
});

// Аккаунты сотрудников теперь создаёт только администратор — публичной
// регистрации больше нет.
app.post('/api/employees', requireAuth('admin'), (req, res) => {
  const { full_name, login, password, positions } = req.body || {};

  if (!full_name || !full_name.trim()) {
    return res.status(400).json({ error: 'Укажите ФИО' });
  }
  if (!login || login.trim().length < 3) {
    return res.status(400).json({ error: 'Логин должен быть не короче 3 символов' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен быть не короче 6 символов' });
  }
  if (db.getUserByLogin(login.trim())) {
    return res.status(409).json({ error: 'Такой логин уже занят' });
  }

  const positionsError = validatePositions(positions);
  if (positionsError) {
    return res.status(400).json({ error: positionsError });
  }

  let user;
  try {
    user = db.createUser({
      role: 'employee',
      full_name: full_name.trim(),
      login: login.trim(),
      password,
      positions: positions || [],
    });
  } catch (err) {
    return res.status(409).json({ error: 'Такой логин уже занят' });
  }

  res.json(user);
});

app.patch('/api/employees/:id/active', requireAuth('admin'), (req, res) => {
  const id = Number(req.params.id);
  const { active } = req.body || {};
  db.setEmployeeActive(id, !!active);
  res.json(db.getUserById(id));
});

// Админ задаёт должности сотрудника — можно несколько (например, основная
// должность + совмещение). Первая должность в списке считается основной:
// по её графику определяется день/ночь для реально отработанных часов.
const SCHEDULE_TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;

function validatePositions(positions) {
  if (positions === undefined) return null;
  if (!Array.isArray(positions)) return 'Список должностей указан неверно';
  for (const p of positions) {
    if (!p || !String(p.name || '').trim()) return 'У каждой должности должно быть название';
    if (p.work_start && !SCHEDULE_TIME_RE.test(p.work_start)) {
      return 'Начало работы укажите в формате ЧЧ:ММ';
    }
    if (p.work_end && !SCHEDULE_TIME_RE.test(p.work_end)) {
      return 'Конец работы укажите в формате ЧЧ:ММ';
    }
    if (p.daily_hours !== undefined && p.daily_hours !== null && p.daily_hours !== '' && Number.isNaN(Number(p.daily_hours))) {
      return 'Часы в день должны быть числом';
    }
  }
  return null;
}

app.patch('/api/employees/:id/positions', requireAuth('admin'), (req, res) => {
  const id = Number(req.params.id);
  const { positions } = req.body || {};

  const error = validatePositions(positions);
  if (error) {
    return res.status(400).json({ error });
  }

  const user = db.updateEmployeePositions(id, positions || []);
  if (!user) {
    return res.status(404).json({ error: 'Сотрудник не найден' });
  }
  res.json(user);
});

// --- QR-код охранника (обновляется каждую минуту, доступен только охране) ---

app.get('/api/guard-qrcode.png', requireAuth('guard'), async (req, res) => {
  const window = currentWindow();
  const token = computeGuardToken(window);
  const payload = `GUARD:${window}:${token}`;
  const secondsLeft = WINDOW_SECONDS - Math.floor((Date.now() / 1000) % WINDOW_SECONDS);
  try {
    const buffer = await QRCode.toBuffer(payload, { width: 400, margin: 2 });
    res.set('X-Seconds-Left', String(secondsLeft));
    res.set('Cache-Control', 'no-store');
    res.type('png').send(buffer);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка генерации QR' });
  }
});

app.get('/api/guard-status', requireAuth('guard'), (req, res) => {
  const secondsLeft = WINDOW_SECONDS - Math.floor((Date.now() / 1000) % WINDOW_SECONDS);
  res.json({ seconds_left: secondsLeft, window_seconds: WINDOW_SECONDS });
});

// --- Отметка сотрудника (сканирование QR охранника со своего телефона) ---
// Личность сотрудника теперь определяется его сессией (после логина),
// а не секретом в ссылке.

app.post('/api/scan', requireAuth('employee'), (req, res) => {
  const { payload } = req.body || {};
  if (!payload) {
    return res.status(400).json({ error: 'Некорректные данные запроса' });
  }

  const employee = db.getUserById(req.user.id);
  if (!employee) {
    return res.status(404).json({ error: 'Сотрудник не найден' });
  }
  if (!employee.active) {
    return res.status(403).json({ error: `${employee.full_name}: пропуск деактивирован` });
  }

  const match = String(payload).match(/^GUARD:(\d+):([A-F0-9]+)$/);
  if (!match) {
    return res.status(400).json({ error: 'Это не код охранника. Наведите камеру на QR на посту.' });
  }
  const window = Number(match[1]);
  const token = match[2];

  const nowWindow = currentWindow();
  if (Math.abs(nowWindow - window) > 1) {
    return res.status(400).json({ error: 'QR-код устарел. Отсканируйте текущий код на посту.' });
  }
  if (!safeEqual(computeGuardToken(window), token)) {
    return res.status(400).json({ error: 'Код не прошёл проверку подлинности.' });
  }

  const consumed = db.tryConsumeWindow(employee.id, window);
  if (!consumed) {
    return res.status(409).json({ error: 'Этот код уже был использован. Дождитесь следующего QR (обновляется каждую минуту).' });
  }

  const lastLog = db.getLastLogForEmployee(employee.id);
  const nextType = !lastLog || lastLog.type === 'out' ? 'in' : 'out';
  const log = db.addLog(employee.id, nextType);

  res.json({
    full_name: employee.full_name,
    type: nextType,
    timestamp: log.timestamp,
  });
});

// --- Журнал (только для админа) ---

app.get('/api/logs', requireAuth('admin'), (req, res) => {
  res.json(db.listLogs());
});

// Часовой пояс сервера — тот же, что использует nowIso() в db.js (UTC).
// Валидируем формат вручную вводимого времени: 'YYYY-MM-DD HH:MM' или
// 'YYYY-MM-DD HH:MM:SS', приводим ко второму варианту.
function normalizeTimestamp(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const m = raw.trim().match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(:\d{2})?$/);
  if (!m) return null;
  const seconds = m[3] || ':00';
  return `${m[1]} ${m[2]}${seconds}`;
}

// Ручное добавление отметки (приход/уход) администратором — например, если
// сотрудник забыл отсканировать QR или телефон не сработал.
app.post('/api/logs', requireAuth('admin'), (req, res) => {
  const { employee_id, type, timestamp } = req.body || {};
  const employee = db.getUserById(employee_id);
  if (!employee || employee.role !== 'employee') {
    return res.status(404).json({ error: 'Сотрудник не найден' });
  }
  if (type !== 'in' && type !== 'out') {
    return res.status(400).json({ error: 'Тип отметки должен быть "in" или "out"' });
  }
  const ts = normalizeTimestamp(timestamp) || (() => {
    const now = new Date();
    return now.toISOString().slice(0, 19).replace('T', ' ');
  })();
  const log = db.addManualLog(employee.id, type, ts);
  res.json({ ...log, full_name: employee.full_name, login: employee.login });
});

// Редактирование существующей отметки (время и/или тип).
app.patch('/api/logs/:id', requireAuth('admin'), (req, res) => {
  const id = Number(req.params.id);
  const { type, timestamp } = req.body || {};
  if (type && type !== 'in' && type !== 'out') {
    return res.status(400).json({ error: 'Тип отметки должен быть "in" или "out"' });
  }
  let ts;
  if (timestamp) {
    ts = normalizeTimestamp(timestamp);
    if (!ts) {
      return res.status(400).json({ error: 'Некорректный формат времени' });
    }
  }
  const log = db.updateLog(id, { type, timestamp: ts });
  if (!log) {
    return res.status(404).json({ error: 'Запись не найдена' });
  }
  const employee = db.getUserById(log.employee_id);
  res.json({ ...log, full_name: employee ? employee.full_name : '—' });
});

// Удаление ошибочной отметки.
app.delete('/api/logs/:id', requireAuth('admin'), (req, res) => {
  const removed = db.deleteLog(req.params.id);
  if (!removed) {
    return res.status(404).json({ error: 'Запись не найдена' });
  }
  res.json({ ok: true });
});

// Сводим сырые отметки "приход"/"уход" в пары смен по каждому сотруднику
// (та же логика, что в logs.html на клиенте).
function pairShiftsByEmployee(logs) {
  const byEmployee = new Map();
  for (const log of logs) {
    if (!byEmployee.has(log.employee_id)) byEmployee.set(log.employee_id, []);
    byEmployee.get(log.employee_id).push(log);
  }
  const shifts = [];
  for (const own of byEmployee.values()) {
    let openIn = null;
    for (const log of own) {
      if (log.type === 'in') {
        if (openIn) shifts.push({ employee_id: log.employee_id, full_name: log.full_name, login: log.login, in: openIn, out: null });
        openIn = log;
      } else if (log.type === 'out' && openIn) {
        shifts.push({ employee_id: log.employee_id, full_name: log.full_name, login: log.login, in: openIn, out: log });
        openIn = null;
      }
    }
    if (openIn) shifts.push({ employee_id: openIn.employee_id, full_name: openIn.full_name, login: openIn.login, in: openIn, out: null });
  }
  shifts.sort((a, b) => new Date(a.in.timestamp) - new Date(b.in.timestamp));
  return shifts;
}

// --- Экспорт данных в Excel (только для админа) ---

app.get('/api/export.xlsx', requireAuth('admin'), async (req, res) => {
  const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
  let { from, to } = req.query || {};
  from = DATE_RE.test(from || '') ? from : null;
  to = DATE_RE.test(to || '') ? to : null;
  if (from && to && from > to) { [from, to] = [to, from]; }

  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'Учёт рабочего времени';
  workbook.created = new Date();

  const allLogsForSummary = db.listAllLogsForExport(from, to);
  const summaryShifts = pairShiftsByEmployee(allLogsForSummary);

  // --- Листы "Табель" (по одному на месяц), формат как в образце заказчика:
  // № / ФИО / Должность / по два столбца "д"(день)/"н"(ночь) на каждый день месяца,
  // в них — отработанные часы за смену. Дневная/ночная колонка определяется
  // графиком, который задаёт администратор (после 18:00 или до 6:00 — ночная).

  const RU_MONTHS = ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь'];
  const RU_WEEKDAYS = ['вс', 'пн', 'вт', 'ср', 'чт', 'пт', 'сб']; // индекс = getUTCDay()

  function daysInMonth(year, month0) {
    return new Date(Date.UTC(year, month0 + 1, 0)).getUTCDate();
  }
  function isNightSchedule(position) {
    if (!position || !position.work_start) return false;
    const hour = Number(String(position.work_start).slice(0, 2));
    return hour >= 18 || hour < 6;
  }

  // Часы по сменам: employeeId -> 'YYYY-MM-DD' -> суммарные часы (только завершённые смены)
  const hoursByEmployeeDate = new Map();
  for (const s of summaryShifts) {
    if (!s.out) continue; // смена ещё не завершена — не включаем в табель
    const inDate = new Date(s.in.timestamp.replace(' ', 'T') + 'Z');
    const outDate = new Date(s.out.timestamp.replace(' ', 'T') + 'Z');
    const dateKey = inDate.toISOString().slice(0, 10);
    const hours = Math.round(((outDate - inDate) / 3600000) * 10) / 10;
    if (!hoursByEmployeeDate.has(s.employee_id)) hoursByEmployeeDate.set(s.employee_id, new Map());
    const perDate = hoursByEmployeeDate.get(s.employee_id);
    perDate.set(dateKey, (perDate.get(dateKey) || 0) + hours);
  }

  // Определяем список месяцев для листов: если указан период — все месяцы
  // в нём; иначе — месяцы, в которых реально есть отметки; если отметок
  // нет вовсе — текущий месяц.
  const monthKeys = new Set();
  if (from || to) {
    const start = from ? new Date(from + 'T00:00:00Z') : (() => {
      const d = new Date(to + 'T00:00:00Z'); d.setUTCDate(1); return d;
    })();
    const end = to ? new Date(to + 'T00:00:00Z') : start;
    let cursor = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), 1));
    const endCursor = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), 1));
    while (cursor <= endCursor) {
      monthKeys.add(`${cursor.getUTCFullYear()}-${String(cursor.getUTCMonth() + 1).padStart(2, '0')}`);
      cursor = new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() + 1, 1));
    }
  } else {
    for (const s of summaryShifts) {
      const d = new Date(s.in.timestamp.replace(' ', 'T') + 'Z');
      monthKeys.add(`${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`);
    }
    if (!monthKeys.size) {
      const now = new Date();
      monthKeys.add(`${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`);
    }
  }

  const employees = db.listEmployees().slice().sort((a, b) => a.id - b.id);

  for (const monthKey of Array.from(monthKeys).sort()) {
    const [year, month1] = monthKey.split('-').map(Number);
    const month0 = month1 - 1;
    const numDays = daysInMonth(year, month0);
    const sheetName = `${RU_MONTHS[month0]} ${String(year).slice(2)}`;
    const sheet = workbook.addWorksheet(sheetName.slice(0, 31));

    const FIXED_COLS = 3; // №, ФИО, Должность
    const COLS_PER_DAY = 2; // д, н

    // Заголовки: число месяца (объединено на д/н), день недели (объединено), затем подписи д/н
    sheet.mergeCells(1, 1, 3, 1);
    sheet.getCell(1, 1).value = '№';
    sheet.mergeCells(1, 2, 3, 2);
    sheet.getCell(1, 2).value = 'Ф.И.О';
    sheet.mergeCells(1, 3, 3, 3);
    sheet.getCell(1, 3).value = 'Должность';

    for (let day = 1; day <= numDays; day++) {
      const startCol = FIXED_COLS + 1 + (day - 1) * COLS_PER_DAY;
      const dateObj = new Date(Date.UTC(year, month0, day));
      sheet.mergeCells(1, startCol, 1, startCol + 1);
      sheet.getCell(1, startCol).value = day;
      sheet.getCell(1, startCol).alignment = { horizontal: 'center' };
      sheet.mergeCells(2, startCol, 2, startCol + 1);
      sheet.getCell(2, startCol).value = RU_WEEKDAYS[dateObj.getUTCDay()];
      sheet.getCell(2, startCol).alignment = { horizontal: 'center' };
      sheet.getCell(3, startCol).value = 'д';
      sheet.getCell(3, startCol + 1).value = 'н';
    }
    sheet.getRow(1).font = { bold: true };
    sheet.getRow(2).font = { bold: true, color: { argb: 'FF8A94AB' } };
    sheet.getRow(3).font = { bold: true };

    sheet.getColumn(1).width = 5;
    sheet.getColumn(2).width = 30;
    sheet.getColumn(3).width = 26;
    for (let day = 1; day <= numDays; day++) {
      const startCol = FIXED_COLS + 1 + (day - 1) * COLS_PER_DAY;
      sheet.getColumn(startCol).width = 5;
      sheet.getColumn(startCol + 1).width = 5;
    }

    let rowNum = 4;
    employees.forEach((emp, idx) => {
      const perDate = hoursByEmployeeDate.get(emp.id);
      const positions = emp.positions && emp.positions.length ? emp.positions : [null];

      positions.forEach((pos, posIdx) => {
        const row = sheet.getRow(rowNum++);
        row.getCell(1).value = idx + 1;
        row.getCell(2).value = emp.full_name;
        row.getCell(3).value = pos ? pos.name : '';

        const night = isNightSchedule(pos);
        for (let day = 1; day <= numDays; day++) {
          const dateKey = `${year}-${String(month1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
          const worked = perDate ? perDate.get(dateKey) : undefined;
          if (worked === undefined) continue; // в этот день у сотрудника не было завершённой смены

          // Основная (первая) должность — реально отработанные часы по отметкам QR.
          // Дополнительные должности (совмещение) — заданные вручную часы в день,
          // проставляются в те же дни, когда была смена.
          const hours = posIdx === 0 ? worked : (pos && pos.daily_hours !== null && pos.daily_hours !== undefined ? pos.daily_hours : null);
          if (hours === null) continue;

          const startCol = FIXED_COLS + 1 + (day - 1) * COLS_PER_DAY;
          row.getCell(night ? startCol + 1 : startCol).value = hours;
        }
      });
    });
  }

  // Лист "Смены" — приход/уход, сведённые в пары
  const periodLabel = from || to ? ` (${from || '…'} — ${to || '…'})` : ' (весь период)';
  const shiftsSheet = workbook.addWorksheet('Смены');
  shiftsSheet.getCell('A1').value = `Период:${periodLabel}`;
  shiftsSheet.getCell('A1').font = { italic: true, color: { argb: 'FF888888' } };
  shiftsSheet.getRow(2).values = ['ФИО', 'Логин', 'Дата', 'Приход', 'Уход', 'Отработано (часы)'];
  shiftsSheet.getRow(2).font = { bold: true };
  shiftsSheet.columns = [
    { key: 'full_name', width: 30 },
    { key: 'login', width: 18 },
    { key: 'date', width: 14 },
    { key: 'time_in', width: 12 },
    { key: 'time_out', width: 12 },
    { key: 'hours', width: 18 },
  ];
  const allLogs = allLogsForSummary;
  const shifts = summaryShifts;
  for (const s of shifts) {
    const inDate = new Date(s.in.timestamp.replace(' ', 'T') + 'Z');
    const outDate = s.out ? new Date(s.out.timestamp.replace(' ', 'T') + 'Z') : null;
    const hours = outDate ? Math.round(((outDate - inDate) / 3600000) * 100) / 100 : '';
    shiftsSheet.addRow({
      full_name: s.full_name,
      login: s.login,
      date: inDate.toISOString().slice(0, 10),
      time_in: inDate.toISOString().slice(11, 16),
      time_out: outDate ? outDate.toISOString().slice(11, 16) : 'ещё на месте',
      hours,
    });
  }

  // Лист "Отметки" — сырые записи, для полноты
  const logsSheet = workbook.addWorksheet('Отметки (сырые)');
  logsSheet.getCell('A1').value = `Период:${periodLabel}`;
  logsSheet.getCell('A1').font = { italic: true, color: { argb: 'FF888888' } };
  logsSheet.getRow(2).values = ['ФИО', 'Логин', 'Тип', 'Время (UTC)'];
  logsSheet.getRow(2).font = { bold: true };
  logsSheet.columns = [
    { key: 'full_name', width: 30 },
    { key: 'login', width: 18 },
    { key: 'type', width: 10 },
    { key: 'timestamp', width: 20 },
  ];
  for (const log of allLogs) {
    logsSheet.addRow({
      full_name: log.full_name,
      login: log.login,
      type: log.type === 'in' ? 'приход' : 'уход',
      timestamp: log.timestamp,
    });
  }

  const rangeSuffix = from || to ? `_${from || 'start'}_${to || 'end'}` : '_all';
  const filename = `time-tracker${rangeSuffix}.xlsx`;
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  await workbook.xlsx.write(res);
  res.end();
});

// --- Автоочистка старого журнала (раз в 6 месяцев) ---
// Храним дату последней очистки в settings; при старте и раз в сутки
// проверяем, не пора ли снова очищать. Так очистка переживает рестарты
// pm2 и не зависит от того, сколько времени сервер был запущен непрерывно.
const LOG_RETENTION_MONTHS = 6;
const CLEANUP_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // раз в сутки

function runScheduledCleanupIfDue() {
  const lastRun = db.getSetting('last_log_cleanup');
  const now = new Date();

  if (lastRun) {
    const next = new Date(lastRun);
    next.setMonth(next.getMonth() + LOG_RETENTION_MONTHS);
    if (now < next) return; // ещё не пора
  }

  const removed = db.purgeLogsOlderThan(LOG_RETENTION_MONTHS);
  db.setSetting('last_log_cleanup', now.toISOString());
  console.log(`Автоочистка журнала: удалено записей старше ${LOG_RETENTION_MONTHS} мес. — ${removed}`);
}

runScheduledCleanupIfDue();
setInterval(runScheduledCleanupIfDue, CLEANUP_CHECK_INTERVAL_MS);

app.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
});
