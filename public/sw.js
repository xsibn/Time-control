// Минимальный service worker — нужен только для установки PWA.
// Осознанно не кэширует API-запросы (авторизация, QR, журнал должны
// всегда идти в сеть, оффлайн-режим для них не имеет смысла).

const CACHE_NAME = 'time-tracker-shell-v1';
const SHELL_FILES = [
  '/icons/icon-192.png',
  '/icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Просто проксируем сеть; иконки отдаём из кэша, если сеть недоступна.
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/icons/')) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request))
    );
  }
});
