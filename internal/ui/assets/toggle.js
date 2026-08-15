  // Light/dark toggle: flips data-theme and persists the choice. The pre-paint
  // head script reads mctl-theme back on the next load.
  function toggleTheme() {
    var root = document.documentElement;
    var cur = root.getAttribute('data-theme') || 'dark';
    var next = cur === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('mctl-theme', next); } catch (e) {}
  }

  // Wire up handlers without inline onclick attributes, so the markup stays
  // compatible with a strict Content-Security-Policy (script-src 'self').
  var tt = document.querySelector('.theme-toggle');
  if (tt) { tt.addEventListener('click', toggleTheme); }
