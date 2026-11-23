// Copy buttons stay hidden without JavaScript or clipboard access; the
// prompt text is selectable either way.
if (navigator.clipboard) {
  document.querySelectorAll('.copy-prompt').forEach(function (btn) {
    btn.hidden = false;
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(btn.dataset.prompt).then(function () {
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
      }).catch(function () {
        btn.textContent = 'Copy failed: select the text';
        setTimeout(function () { btn.textContent = 'Copy'; }, 4000);
      });
    });
  });
}
