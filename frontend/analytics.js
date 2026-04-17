// Lightweight analytics wrapper around Vercel Web Analytics.
// Usage: trackEvent('event_name', { prop: value })
// Safe to call before the Vercel script finishes loading (queues and flushes).
(function () {
  var queue = [];

  function flush() {
    if (typeof window.va !== 'function') return;
    while (queue.length) {
      var evt = queue.shift();
      try { window.va('event', evt); } catch (e) { /* ignore */ }
    }
  }

  function trackEvent(name, props) {
    if (!name) return;
    var payload = Object.assign({ name: String(name) }, props || {});
    if (typeof window.va === 'function') {
      try { window.va('event', payload); } catch (e) { /* ignore */ }
    } else {
      queue.push(payload);
    }
  }

  window.trackEvent = trackEvent;

  // Poll briefly for the Vercel script to load, then flush queued events.
  var tries = 0;
  var timer = setInterval(function () {
    tries++;
    if (typeof window.va === 'function') {
      flush();
      clearInterval(timer);
    } else if (tries > 40) { // ~10s
      clearInterval(timer);
    }
  }, 250);
})();
