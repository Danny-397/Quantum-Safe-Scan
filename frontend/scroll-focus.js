/* Keyboard access for regions that scroll sideways (WCAG 2.1.1).
   A wide code block or table that overflows at the current width can only be
   scrolled with a pointer unless it can take focus, so each one that actually
   overflows gets tabindex="0" (and arrow keys then scroll it). Regions that
   fit get no extra tab stop. Re-checked on resize, since a block that fits on
   a desktop overflows on a phone. */
(function () {
  "use strict";
  var SELECTOR = "pre, code, .tablewrap, .table-wrap, [data-scroll-x]";

  function check() {
    var els = document.querySelectorAll(SELECTOR);
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      var ox = getComputedStyle(el).overflowX;
      var scrolls = (ox === "auto" || ox === "scroll") && el.scrollWidth > el.clientWidth + 1;
      if (scrolls && !el.hasAttribute("tabindex")) {
        el.setAttribute("tabindex", "0");
        el.setAttribute("data-scroll-focus", "");
      } else if (!scrolls && el.hasAttribute("data-scroll-focus")) {
        el.removeAttribute("tabindex");
        el.removeAttribute("data-scroll-focus");
      }
    }
  }

  // Throttled, not debounced: a live dashboard mutates the page every few
  // seconds, and a debounce would keep postponing the check forever.
  var timer = null;
  function soon() { if (!timer) timer = setTimeout(function () { timer = null; check(); }, 300); }

  // A focus ring for these regions, in case the site styles only controls.
  var style = document.createElement("style");
  style.textContent = ":where([data-scroll-focus]):focus-visible{outline:2px solid;outline-offset:2px}";
  (document.head || document.documentElement).appendChild(style);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", check);
  else check();
  window.addEventListener("load", check);
  window.addEventListener("resize", soon);
  // Content rendered later (tables built from data) is picked up too.
  if ("MutationObserver" in window) new MutationObserver(soon).observe(document.documentElement, { childList: true, subtree: true });
})();
