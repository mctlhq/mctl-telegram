  // Resolve theme and set data-theme BEFORE paint to avoid flash.
  // mctl.css has no prefers-color-scheme fallback, so the attribute must
  // always be present. There is no light/dark toggle: theme always follows the
  // OS preference (we deliberately do NOT read a stored mctl-theme, so users
  // who toggled before it was removed are not pinned to a stale value). Only
  // the accent colour is persisted, since the swatch picker still sets it.
  (function () {
    var root = document.documentElement;
    var a;
    try {
      a = localStorage.getItem('mctl-accent');
    } catch (e) {}
    root.setAttribute('data-theme', matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    if (a === 'lime' || a === 'vermilion' || a === 'lilac') {
      root.setAttribute('data-accent', a);
    }
  })();
