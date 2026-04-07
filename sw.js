// Minimal service worker — required for PWA installability.
// No caching strategy; all requests go straight to the network.
self.addEventListener('install',  e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',    e => e.respondWith(fetch(e.request)));
