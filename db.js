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
    return { users: [], time_logs: [], settings: {}, next_user_id: 1, next_log_id: 1 };
  }
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
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

function createUser({ role, full_name, login, password, work_start = null, work_end = null }) {
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
    work_start,
    work_end,
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

function setEmployeeActive(id, active) {
  const user = state.users.find(u => u.id === Number(id) && u.role === 'employee');
  if (user) {
    user.active = active ? 1 : 0;
    persist();
  }
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
      return {
        ...l,
        full_name: user ? user.full_name : '—',
        work_start: user ? user.work_start : null,
        work_end: user ? user.work_end : null,
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
      return {
        ...l,
        full_name: user ? user.full_name : '—',
        login: user ? user.login : '—',
        work_start: user ? user.work_start : null,
        work_end: user ? user.work_end : null,
      };
    });
}

module.exports = {
  createUser,
  getUserById,
  getUserByLogin,
  getOrCreateSingletonAccount,
  verifyPassword,
  listEmployees,
  setEmployeeActive,
  tryConsumeWindow,
  getLastLogForEmployee,
  addLog,
  listLogs,
  listAllLogsForExport,
  getOrCreateGuardSecret,
  getOrCreateSessionSecret,
};
