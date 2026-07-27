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

const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/; // ЧЧ:ММ, 24-часовой формат

// --- Аутентификация ---

app.post('/api/auth/register', (req, res) => {
  const { full_name, work_start, work_end, login, password } = req.body || {};

  if (!full_name || !full_name.trim()) {
    return res.status(400).json({ error: 'Укажите ФИО' });
  }
  if (!TIME_RE.test(work_start || '')) {
    return res.status(400).json({ error: 'Время начала работы укажите в формате ЧЧ:ММ (24 часа)' });
  }
  if (!TIME_RE.test(work_end || '')) {
    return res.status(400).json({ error: 'Время окончания работы укажите в формате ЧЧ:ММ (24 часа)' });
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

  let user;
  try {
    user = db.createUser({
      role: 'employee',
      full_name: full_name.trim(),
      login: login.trim(),
      password,
      work_start,
      work_end,
    });
  } catch (err) {
    return res.status(409).json({ error: 'Такой логин уже занят' });
  }

  const sid = createSession(user);
  res.setHeader('Set-Cookie', `${SID_COOKIE}=${signSid(sid)}; HttpOnly; Path=/; SameSite=Lax`);
  res.json({ id: user.id, full_name: user.full_name, role: user.role });
});

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

// --- Сотрудники (только для охраны/админа) ---

app.get('/api/employees', requireAuth('admin'), (req, res) => {
  res.json(db.listEmployees());
});

app.patch('/api/employees/:id/active', requireAuth('admin'), (req, res) => {
  const id = Number(req.params.id);
  const { active } = req.body || {};
  db.setEmployeeActive(id, !!active);
  res.json(db.getUserById(id));
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

  // Лист "Сотрудники" — сводная таблица: сотрудник, график, дни
  // (в каждом дне — приход/уход/отработано часов)
  const employeesSheet = workbook.addWorksheet('Сотрудники');

  const allLogsForSummary = db.listAllLogsForExport(from, to);
  const summaryShifts = pairShiftsByEmployee(allLogsForSummary);

  // Собираем набор дат, встречающихся в сменах, по возрастанию
  const dateSet = new Set();
  for (const s of summaryShifts) {
    const inDate = new Date(s.in.timestamp.replace(' ', 'T') + 'Z');
    dateSet.add(inDate.toISOString().slice(0, 10));
  }
  const dates = Array.from(dateSet).sort();

  // Смены по сотруднику и дате: employeeKey -> date -> { time_in, time_out, hours }
  const byEmployeeDate = new Map();
  const employeeMeta = new Map(); // employeeKey -> { full_name, login }
  for (const s of summaryShifts) {
    const key = s.login || s.full_name;
    const inDate = new Date(s.in.timestamp.replace(' ', 'T') + 'Z');
    const outDate = s.out ? new Date(s.out.timestamp.replace(' ', 'T') + 'Z') : null;
    const dateKey = inDate.toISOString().slice(0, 10);
    const hours = outDate ? Math.round(((outDate - inDate) / 3600000) * 100) / 100 : '';
    if (!employeeMeta.has(key)) employeeMeta.set(key, { full_name: s.full_name, login: s.login });
    if (!byEmployeeDate.has(key)) byEmployeeDate.set(key, new Map());
    byEmployeeDate.get(key).set(dateKey, {
      time_in: inDate.toISOString().slice(11, 16),
      time_out: outDate ? outDate.toISOString().slice(11, 16) : 'ещё на месте',
      hours,
    });
  }
  // Добавляем сотрудников без смен в выбранном периоде (пустые дни)
  for (const emp of db.listEmployees()) {
    const key = emp.login;
    if (!employeeMeta.has(key)) employeeMeta.set(key, { full_name: emp.full_name, login: emp.login });
  }

  const FIXED_COLS = 2; // Сотрудник, График
  const COLS_PER_DAY = 3; // Приход, Уход, Часы

  // Заголовок листа: 2 фиксированных столбца + по 3 столбца на каждый день
  employeesSheet.mergeCells(1, 1, 2, 1);
  employeesSheet.getCell(1, 1).value = 'Сотрудник';
  employeesSheet.mergeCells(1, 2, 2, 2);
  employeesSheet.getCell(1, 2).value = 'График';
  dates.forEach((date, i) => {
    const startCol = FIXED_COLS + 1 + i * COLS_PER_DAY;
    employeesSheet.mergeCells(1, startCol, 1, startCol + COLS_PER_DAY - 1);
    employeesSheet.getCell(1, startCol).value = date;
    employeesSheet.getCell(1, startCol).alignment = { horizontal: 'center' };
    employeesSheet.getCell(2, startCol).value = 'Приход';
    employeesSheet.getCell(2, startCol + 1).value = 'Уход';
    employeesSheet.getCell(2, startCol + 2).value = 'Часы';
  });
  employeesSheet.getRow(1).font = { bold: true };
  employeesSheet.getRow(2).font = { bold: true };

  employeesSheet.getColumn(1).width = 30;
  employeesSheet.getColumn(2).width = 16;
  for (let i = 0; i < dates.length; i++) {
    employeesSheet.getColumn(FIXED_COLS + 1 + i * COLS_PER_DAY).width = 10;
    employeesSheet.getColumn(FIXED_COLS + 2 + i * COLS_PER_DAY).width = 10;
    employeesSheet.getColumn(FIXED_COLS + 3 + i * COLS_PER_DAY).width = 10;
  }

  let rowIdx = 3;
  const employeesByLogin = new Map(db.listEmployees().map(e => [e.login, e]));
  for (const [key, meta] of employeeMeta) {
    const empRecord = employeesByLogin.get(key);
    const schedule = empRecord && empRecord.work_start && empRecord.work_end
      ? `${empRecord.work_start}\u2013${empRecord.work_end}`
      : '';
    const row = employeesSheet.getRow(rowIdx);
    row.getCell(1).value = meta.full_name;
    row.getCell(2).value = schedule;
    const daysForEmp = byEmployeeDate.get(key);
    dates.forEach((date, i) => {
      const startCol = FIXED_COLS + 1 + i * COLS_PER_DAY;
      const day = daysForEmp ? daysForEmp.get(date) : null;
      if (day) {
        row.getCell(startCol).value = day.time_in;
        row.getCell(startCol + 1).value = day.time_out;
        row.getCell(startCol + 2).value = day.hours;
      }
    });
    rowIdx++;
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

app.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
});
