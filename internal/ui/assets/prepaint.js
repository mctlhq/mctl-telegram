  // Resolve theme + accent and set the attributes BEFORE paint to avoid a
  // flash. mctl.css has no prefers-color-scheme fallback, so data-theme must
  // always be present. A stored mctl-theme wins (explicit user toggle);
  // otherwise we follow the OS preference.
  (function () {
    var root = document.documentElement;
    var t, a;
    try {
      t = localStorage.getItem('mctl-theme');
      a = localStorage.getItem('mctl-accent');
    } catch (e) {}
    if (t !== 'light' && t !== 'dark') {
      t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    root.setAttribute('data-theme', t);
    if (a === 'cyan' || a === 'lime' || a === 'lilac') {
      root.setAttribute('data-accent', a);
    }
  })();
