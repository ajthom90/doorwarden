// Applies the stored theme before first paint (classic script, not a
// module, so it runs before the body renders). "system" or nothing leaves
// prefers-color-scheme in charge.
(function () {
  var t = null;
  try { t = window.localStorage.getItem("doorwarden.theme"); } catch (e) { t = null; }
  if (t === "light" || t === "dark") {
    document.documentElement.setAttribute("data-theme", t);
  }
})();
