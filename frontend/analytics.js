/* Vercel Web Analytics.
   Loads the edge-served tracking script that Vercel provides automatically at
   /_vercel/insights/script.js once Web Analytics is enabled for the project.
   No bundler or node_modules needed — this works on the vanilla static site.

   (The previous version did `import { inject } from './node_modules/...'`, but
   node_modules is gitignored and never deployed, so that path 404'd and no
   analytics were ever collected.) */
(function () {
  var host = location.hostname;
  // Skip local dev — the /_vercel path only exists on the Vercel deployment.
  if (host === "localhost" || host === "127.0.0.1" || host === "") return;

  // Queue used by the Vercel script before it finishes loading.
  window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };

  var s = document.createElement("script");
  s.defer = true;
  s.src = "/_vercel/insights/script.js";
  document.head.appendChild(s);
})();
