  // Resolve theme and set data-theme BEFORE paint to avoid a flash. A stored
  // mctl-theme wins (explicit user toggle); otherwise the page is dark, like
  // mctl.ai and docs.mctl.ai. Light stays one click away on the toggle.
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
      t = 'dark';
    }
    root.setAttribute('data-theme', t);
    root.removeAttribute('data-accent');
  })();
