// Copy MCP URL button.
var copyBtn = document.getElementById('copy-mcp-url');
if (copyBtn) {
  copyBtn.addEventListener('click', function () {
    var url = copyBtn.dataset.url;
    var label = copyBtn.textContent;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(url).then(function () {
        copyBtn.textContent = 'Copied!';
        setTimeout(function () { copyBtn.textContent = label; }, 2000);
      }).catch(function () {
        copyBtn.textContent = url;
        setTimeout(function () { copyBtn.textContent = label; }, 4000);
      });
    } else {
      copyBtn.textContent = url;
      setTimeout(function () { copyBtn.textContent = label; }, 4000);
    }
  });
}

// Usage strip refresh: once a minute while the tab is visible, re-read
// /api/stats (same origin, allowed by connect-src 'self') and rewrite the
// four values in place. Any failure leaves the server-rendered numbers as
// they are. Grouping matches ui.FormatCount ("57,339").
var strip = document.getElementById('stats');
if (strip && window.fetch) {
  var fmt = function (n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); };
  var refresh = function () {
    if (document.visibilityState === 'hidden') return;
    fetch('/api/stats', { cache: 'no-store', credentials: 'omit' }).then(function (r) {
      if (!r.ok) return null;
      return r.json();
    }).then(function (s) {
      if (!s) return;
      var els = strip.querySelectorAll('[data-stat]');
      for (var i = 0; i < els.length; i++) {
        var v = s[els[i].getAttribute('data-stat')];
        if (typeof v === 'number') els[i].textContent = fmt(v);
      }
      var t = document.getElementById('stats-updated');
      if (t && s.updated_at) {
        var d = new Date(s.updated_at);
        if (!isNaN(d)) {
          t.setAttribute('datetime', d.toISOString());
          t.textContent = ('0' + d.getUTCHours()).slice(-2) + ':' + ('0' + d.getUTCMinutes()).slice(-2) + ' UTC';
        }
      }
    }).catch(function () {});
  };
  setInterval(refresh, 60000);
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') refresh();
  });
}

// Connect tabs. Without this script every panel is visible under its own
// heading. With it the headings become a tablist: click, arrow keys, and the
// old anchors (#claude, #connect, #chatgpt) pick the tab.
(function () {
  var root = document.getElementById('connect-tabs');
  if (!root) return;
  var list = root.querySelector('[role="tablist"]');
  var tabs = Array.prototype.slice.call(root.querySelectorAll('[role="tab"]'));
  if (!list || !tabs.length) return;
  var ids = { claude: 'panel-claude', code: 'panel-code', chatgpt: 'chatgpt', other: 'panel-other' };
  var hashes = { claude: 'claude', connect: 'other', chatgpt: 'chatgpt', code: 'code', other: 'other' };
  var show = function (name, focus) {
    tabs.forEach(function (t) {
      var on = t.getAttribute('data-tab') === name;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      if (on && focus) t.focus();
      document.getElementById(ids[t.getAttribute('data-tab')]).hidden = !on;
    });
  };
  root.classList.add('js-tabs');
  list.hidden = false;
  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { show(t.getAttribute('data-tab')); });
    t.addEventListener('keydown', function (e) {
      var d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      e.preventDefault();
      show(tabs[(i + d + tabs.length) % tabs.length].getAttribute('data-tab'), true);
    });
  });
  var fromHash = function () {
    var name = hashes[(location.hash || '').replace('#', '')];
    return name || null;
  };
  window.addEventListener('hashchange', function () { var n = fromHash(); if (n) show(n); });
  show(fromHash() || 'claude');
})();
