  // Resolve theme and set data-theme BEFORE paint to avoid flash.
  // mctl.css has no prefers-color-scheme fallback, so the attribute
  // must always be present.
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
    if (a === 'lime' || a === 'vermilion' || a === 'lilac') {
      root.setAttribute('data-accent', a);
    }
  })();
