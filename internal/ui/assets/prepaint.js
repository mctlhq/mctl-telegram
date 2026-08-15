  // Resolve theme and set data-theme BEFORE paint to avoid a flash. mctl.css
  // has no prefers-color-scheme fallback, so data-theme must always be present.
  // A stored mctl-theme wins (explicit user toggle); otherwise we follow the OS.
  // Accent is terracotta from the design system — never restore a stored
  // mctl-accent, so a leftover cyan/lime/lilac pick cannot override it.
  (function () {
    var root = document.documentElement;
    var t;
    try {
      t = localStorage.getItem('mctl-theme');
      localStorage.removeItem('mctl-accent');
    } catch (e) {}
    if (t !== 'light' && t !== 'dark') {
      t = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    root.setAttribute('data-theme', t);
    root.removeAttribute('data-accent');
  })();
