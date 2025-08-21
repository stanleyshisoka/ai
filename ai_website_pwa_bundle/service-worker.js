
const CACHE_NAME = 'ai-assistant-cache-v1';
const ASSETS = [
  '/',
  '/manifest.json',
  '/static/offline.html',
  '/static/styles.css',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null)))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') { return; }
  event.respondWith(
    fetch(request).catch(() => caches.match(request).then(r => r || caches.match('/static/offline.html')))
  );
});
