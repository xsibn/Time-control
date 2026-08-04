// Хранилище на обычном JSON-файле — без нативных модулей и компиляции.
// Для такого объёма данных (сотрудники + журнал отметок) этого достаточно
// и это работает одинаково на любой машине/версии Node без node-gyp.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DATA_FILE = path.join(__dirname, 'data.json');

function nowIso() {
  // Формат, совместимый с тем, что раньше отдавал sqlite datetime('now'): 'YYYY-MM-DD HH:MM:SS'
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    return { users: [], time_logs: [], day_codes: [], schedule_shifts: [], settings: {}, next_user_id: 1, next_log_id: 1, next_daycode_id: 1, next_shift_id: 1 };
  }
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const data = JSON.parse(raw);
    // Совместимость со старыми файлами данных, созданными до появления кодов табеля.
    if (!Array.isArray(data.day_codes)) data.day_codes = [];
    if (!data.next_daycode_id) data.next_daycode_id = 1;
    // Совместимость со старыми файлами данных, созданными до появления графиков работы.
    if (!Array.isArray(data.schedule_shifts)) data.schedule_shifts = [];
    if (!data.next_shift_id) data.next_shift_id = 1;
    return data;
  } catch (err) {
    throw new Error(`Не удалось прочитать data.json: ${err.message}`);
  }
}

let state = loadData();

// Простая защита от гонок при параллельных запросах в одном процессе:
// пишем синхронно и через временный файл (atomic rename).
function persist() {
  const tmp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), 'utf8');
  fs.renameSync(tmp, DATA_FILE);
}

// --- Настройки (секреты и т.п.) ---

function getSetting(key) {
  return Object.prototype.hasOwnProperty.call(state.settings, key) ? state.settings[key] : null;
}

function setSetting(key, value) {
  state.settings[key] = value;
  persist();
}

function getOrCreateGuardSecret() {
  let secret = getSetting('guard_secret');
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    setSetting('guard_secret', secret);
  }
  return secret;
}

function getOrCreateSessionSecret() {
  let secret = getSetting('session_secret');
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    setSetting('session_secret', secret);
  }
  return secret;
}

// --- Пароли (scrypt, без внешних зависимостей) ---

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  const bufA = Buffer.from(hash, 'hex');
  const bufB = Buffer.from(expectedHash, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// --- Пользователи ---

// positions — массив должностей сотрудника: [{ name, work_start, work_end, daily_hours }]
// Первая должность в списке — основная: именно по её графику (день/ночь) и
// реально отработанному времени (по отметкам QR) формируется табель.
// Остальные должности — дополнительные (совмещение): в табеле для них
// проставляются фиксированные часы (daily_hours) в те дни, когда у сотрудника
// была отработанная смена.
function normalizePositions(positions) {
  if (!Array.isArray(positions)) return [];
  return positions
    .filter(p => p && String(p.name || '').trim())
    .map(p => ({
      name: String(p.name).trim(),
      work_start: p.work_start || null,
      work_end: p.work_end || null,
      daily_hours: p.daily_hours !== undefined && p.daily_hours !== null && p.daily_hours !== ''
        ? Number(p.daily_hours)
        : null,
    }));
}

function createUser({ role, full_name, login, password, positions = [] }) {
  if (state.users.some(u => u.login === login)) {
    const err = new Error('Такой логин уже занят');
    err.code = 'DUPLICATE_LOGIN';
    throw err;
  }
  const { hash, salt } = hashPassword(password);
  const user = {
    id: state.next_user_id++,
    role,
    full_name,
    login,
    password_hash: hash,
    password_salt: salt,
    positions: normalizePositions(positions),
    active: 1,
    last_window: 0,
    created_at: nowIso(),
  };
  state.users.push(user);
  persist();
  return user;
}

function getUserById(id) {
  return state.users.find(u => u.id === Number(id)) || null;
}

function getUserByLogin(login) {
  return state.users.find(u => u.login === login) || null;
}

function getOrCreateSingletonAccount(role, full_name, login, password) {
  const existing = state.users.find(u => u.role === role);
  if (existing) return existing;
  return createUser({ role, full_name, login, password });
}

function listEmployees() {
  return state.users
    .filter(u => u.role === 'employee')
    .slice()
    .sort((a, b) => b.id - a.id);
}

// Админ задаёт должности сотрудника (можно несколько — совмещение) и график
// каждой из них. Сам сотрудник это не выбирает — аккаунты и должности
// целиком в ведении администратора.
function updateEmployeePositions(id, positions) {
  const user = state.users.find(u => u.id === Number(id) && u.role === 'employee');
  if (!user) return null;
  user.positions = normalizePositions(positions);
  persist();
  return user;
}

// Основная должность сотрудника (первая в списке) — по ней считается
// реально отработанное время в табеле.
function primaryPosition(user) {
  return user && Array.isArray(user.positions) && user.positions[0] ? user.positions[0] : null;
}

// Категория сотрудника для меню «Графики» — определяется по названию
// основной должности. Ключевые слова захватывают типовые варианты
// написания («охрана», «охранник», «аутсорсинг» и т.п.).
function employeeCategory(user) {
  const pos = primaryPosition(user);
  const name = (pos && pos.name ? pos.name : '').toLowerCase();
  if (name.includes('охран')) return 'guard';
  if (name.includes('аутсорс') || name.includes('outsource')) return 'outsource';
  return 'staff';
}

function setEmployeeActive(id, active) {
  const user = state.users.find(u => u.id === Number(id) && u.role === 'employee');
  if (user) {
    user.active = active ? 1 : 0;
    persist();
  }
}

// Полное удаление сотрудника. Отметки прихода/ухода и коды табеля за
// прошлые периоды не трогаем — они остаются историческими записями (в
// журнале и экспорте сотрудник просто перестаёт числиться в списке
// активных, но его прошлые смены никуда не пропадают).
function deleteEmployee(id) {
  const idx = state.users.findIndex(u => u.id === Number(id) && u.role === 'employee');
  if (idx === -1) return false;
  state.users.splice(idx, 1);
  persist();
  return true;
}

// Атомарно (в рамках однопроцессного Node) проверяет, что окно новее
// последнего использованного, и сразу фиксирует его — защита от повторного
// использования одного и того же QR.
function tryConsumeWindow(employeeId, window) {
  const user = state.users.find(u => u.id === Number(employeeId));
  if (!user || user.last_window >= window) return false;
  user.last_window = window;
  persist();
  return true;
}

function getLastLogForEmployee(employeeId) {
  const logs = state.time_logs.filter(l => l.employee_id === Number(employeeId));
  if (!logs.length) return null;
  return logs.reduce((latest, l) => (l.id > latest.id ? l : latest));
}

function addLog(employeeId, type) {
  const log = {
    id: state.next_log_id++,
    employee_id: Number(employeeId),
    type,
    timestamp: nowIso(),
  };
  state.time_logs.push(log);
  persist();
  return log;
}

function listLogs(limit = 200) {
  return state.time_logs
    .slice()
    .sort((a, b) => b.id - a.id)
    .slice(0, limit)
    .map(l => {
      const user = getUserById(l.employee_id);
      const pos = primaryPosition(user);
      return {
        ...l,
        full_name: user ? user.full_name : '—',
        work_start: pos ? pos.work_start : null,
        work_end: pos ? pos.work_end : null,
      };
    });
}

// Полный список отметок для экспорта — без ограничения по количеству,
// в хронологическом порядке. from/to — строки 'YYYY-MM-DD' (включительно),
// фильтрация по дате отметки; любой из них можно не передавать.
function listAllLogsForExport(from = null, to = null) {
  return state.time_logs
    .slice()
    .filter(l => {
      const day = l.timestamp.slice(0, 10);
      if (from && day < from) return false;
      if (to && day > to) return false;
      return true;
    })
    .sort((a, b) => a.id - b.id)
    .map(l => {
      const user = getUserById(l.employee_id);
      const pos = primaryPosition(user);
      return {
        ...l,
        full_name: user ? user.full_name : '—',
        login: user ? user.login : '—',
        work_start: pos ? pos.work_start : null,
        work_end: pos ? pos.work_end : null,
      };
    });
}

function updateUserPassword(id, newPassword) {
  const user = state.users.find(u => u.id === Number(id));
  if (!user) return false;
  const { hash, salt } = hashPassword(newPassword);
  user.password_hash = hash;
  user.password_salt = salt;
  persist();
  return true;
}

// Удаляет отметки прихода/ухода старше N месяцев — вызывается по расписанию
// из server.js. Возвращает количество удалённых записей.
function purgeLogsOlderThan(months) {
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - months);
  const cutoffStr = cutoff.toISOString().slice(0, 19).replace('T', ' ');

  const before = state.time_logs.length;
  state.time_logs = state.time_logs.filter(l => l.timestamp >= cutoffStr);
  const removed = before - state.time_logs.length;

  if (removed > 0) persist();
  return removed;
}

// Ручное создание отметки администратором — timestamp передаётся явно
// (в отличие от addLog, который всегда ставит текущее время при сканировании QR).
function addManualLog(employeeId, type, timestamp) {
  const log = {
    id: state.next_log_id++,
    employee_id: Number(employeeId),
    type,
    timestamp,
    manual: true,
  };
  state.time_logs.push(log);
  persist();
  return log;
}

function getLogById(id) {
  return state.time_logs.find(l => l.id === Number(id)) || null;
}

function updateLog(id, { type, timestamp }) {
  const log = getLogById(id);
  if (!log) return null;
  if (type) log.type = type;
  if (timestamp) log.timestamp = timestamp;
  log.edited = true;
  persist();
  return log;
}

function deleteLog(id) {
  const before = state.time_logs.length;
  state.time_logs = state.time_logs.filter(l => l.id !== Number(id));
  const removed = before !== state.time_logs.length;
  if (removed) persist();
  return removed;
}

// --- Коды табеля (ручные отметки: отпуск, больничный и т.п.) ---
// Одна запись на пару (сотрудник, дата). code='' или null — снимает отметку
// (ячейка снова считается автоматически по отметкам приход/уход).
// date — строка 'YYYY-MM-DD'.

function findDayCode(employeeId, date) {
  return state.day_codes.find(d => d.employee_id === Number(employeeId) && d.date === date) || null;
}

function setDayCode(employeeId, date, code) {
  const existing = findDayCode(employeeId, date);
  const clean = code ? String(code).trim().toUpperCase().slice(0, 4) : '';
  if (!clean) {
    if (existing) {
      state.day_codes = state.day_codes.filter(d => d !== existing);
      persist();
    }
    return null;
  }
  if (existing) {
    existing.code = clean;
    persist();
    return existing;
  }
  const rec = { id: state.next_daycode_id++, employee_id: Number(employeeId), date, code: clean };
  state.day_codes.push(rec);
  persist();
  return rec;
}

// Проставляет один код на весь диапазон дат [from, to] включительно —
// используется для отпуска и других многодневных отметок.
function setDayCodeRange(employeeId, from, to, code) {
  const start = new Date(from + 'T00:00:00Z');
  const end = new Date(to + 'T00:00:00Z');
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    const err = new Error('Некорректный период дат');
    err.code = 'INVALID_RANGE';
    throw err;
  }
  const results = [];
  const cursor = new Date(start);
  while (cursor <= end) {
    const dateKey = cursor.toISOString().slice(0, 10);
    results.push(setDayCode(employeeId, dateKey, code));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return results;
}

function listDayCodesForMonth(year, month1) {
  const prefix = `${year}-${String(month1).padStart(2, '0')}`;
  return state.day_codes.filter(d => d.date.startsWith(prefix));
}

function listDayCodesForEmployee(employeeId, year, month1) {
  const prefix = `${year}-${String(month1).padStart(2, '0')}`;
  return state.day_codes.filter(d => d.employee_id === Number(employeeId) && d.date.startsWith(prefix));
}

// --- Графики работы (плановые смены: Д/Н/В и т.п., составляет админ) ---
// Отдельно от day_codes: коды табеля фиксируют, что фактически произошло
// (отпуск, больничный...), а график — это план на будущее по сотрудникам,
// охранникам и аутсорсу, который админ составляет заранее по категориям.
// Одна запись на пару (сотрудник, дата). shift='' или null — снимает смену.

function findScheduleShift(employeeId, date) {
  return state.schedule_shifts.find(s => s.employee_id === Number(employeeId) && s.date === date) || null;
}

function setScheduleShift(employeeId, date, shift) {
  const existing = findScheduleShift(employeeId, date);
  const clean = shift ? String(shift).trim().toUpperCase().slice(0, 4) : '';
  if (!clean) {
    if (existing) {
      state.schedule_shifts = state.schedule_shifts.filter(s => s !== existing);
      persist();
    }
    return null;
  }
  if (existing) {
    existing.shift = clean;
    persist();
    return existing;
  }
  const rec = { id: state.next_shift_id++, employee_id: Number(employeeId), date, shift: clean };
  state.schedule_shifts.push(rec);
  persist();
  return rec;
}

// Проставляет одну смену на весь диапазон дат [from, to] включительно —
// удобно для типовых графиков (например, «через два на два»/сплошные будни).
function setScheduleShiftRange(employeeId, from, to, shift) {
  const start = new Date(from + 'T00:00:00Z');
  const end = new Date(to + 'T00:00:00Z');
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    const err = new Error('Некорректный период дат');
    err.code = 'INVALID_RANGE';
    throw err;
  }
  const results = [];
  const cursor = new Date(start);
  while (cursor <= end) {
    const dateKey = cursor.toISOString().slice(0, 10);
    results.push(setScheduleShift(employeeId, dateKey, shift));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return results;
}

function listScheduleForMonth(year, month1) {
  const prefix = `${year}-${String(month1).padStart(2, '0')}`;
  return state.schedule_shifts.filter(s => s.date.startsWith(prefix));
}

function listScheduleForEmployee(employeeId, year, month1) {
  const prefix = `${year}-${String(month1).padStart(2, '0')}`;
  return state.schedule_shifts.filter(s => s.employee_id === Number(employeeId) && s.date.startsWith(prefix));
}

// Сотрудники одной категории (staff/guard/outsource) — используется
// страницей «Графики», где график составляется отдельно по каждой категории.
function listEmployeesByCategory(category) {
  return listEmployees().filter(u => employeeCategory(u) === category);
}

module.exports = {
  getSetting,
  setSetting,
  createUser,
  getUserById,
  getUserByLogin,
  getOrCreateSingletonAccount,
  verifyPassword,
  updateUserPassword,
  listEmployees,
  setEmployeeActive,
  deleteEmployee,
  updateEmployeePositions,
  primaryPosition,
  employeeCategory,
  listEmployeesByCategory,
  setScheduleShift,
  setScheduleShiftRange,
  listScheduleForMonth,
  listScheduleForEmployee,
  tryConsumeWindow,
  getLastLogForEmployee,
  addLog,
  addManualLog,
  getLogById,
  updateLog,
  deleteLog,
  listLogs,
  listAllLogsForExport,
  purgeLogsOlderThan,
  getOrCreateGuardSecret,
  getOrCreateSessionSecret,
  setDayCode,
  setDayCodeRange,
  listDayCodesForMonth,
  listDayCodesForEmployee,
};
