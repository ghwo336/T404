// Bundles the UI (web/app.ts) and the engine worker (web/worker.ts) into a single offline HTML: web/noexit.html
import { build } from "esbuild";
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const samples = {};
const walk = (d) => { for (const e of readdirSync(d)) { const p = join(d, e); if (statSync(p).isDirectory()) walk(p); else if (p.endsWith(".sol")) samples[relative("samples", p)] = readFileSync(p, "utf8"); } };
walk("samples");

const w = await build({ entryPoints: ["web/worker.ts"], bundle: true, write: false, format: "iife", platform: "browser", target: "es2020", minify: true });
const workerJs = w.outputFiles[0].text;
const r = await build({
  entryPoints: ["web/app.ts"], bundle: true, write: false, format: "iife", platform: "browser", target: "es2020", minify: true,
  define: { __SAMPLES__: JSON.stringify(samples), __WORKER__: JSON.stringify(workerJs) },
});
const js = r.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
const html = readFileSync("web/template.html", "utf8").replace("/*__BUNDLE__*/", () => js);
writeFileSync("web/noexit.html", html);
console.log(`web/noexit.html: ${(html.length / 1024).toFixed(0)} KB, ${Object.keys(samples).length} samples bundled, worker ${(workerJs.length / 1024).toFixed(0)} KB`);
