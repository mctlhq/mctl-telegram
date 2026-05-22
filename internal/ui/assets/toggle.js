  // Accent picker: sets data-accent (cyan is the mctl default — no attribute),
  // persists in localStorage. There is no light/dark toggle; theme follows the
  // OS preference, resolved before paint by the head script.
  function setAccent(name) {
    var root = document.documentElement;
    if (name === 'cyan') {
      root.removeAttribute('data-accent');
    } else {
      root.setAttribute('data-accent', name);
    }
    try { localStorage.setItem('mctl-accent', name); } catch (e) {}
  }

  // Wire up handlers without inline onclick attributes, so the markup stays
  // compatible with a strict Content-Security-Policy (script-src 'self').
  document.querySelectorAll('.accent-swatch').forEach(function (btn) {
    btn.addEventListener('click', function () { setAccent(btn.dataset.pick); });
  });
