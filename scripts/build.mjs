// Construit une page unique (CSS + JS inline) sous deux formes :
// - dist/cartographe-attack.html : fragment publié comme Artifact claude.ai (qui ajoute doctype, <head> et <body>) ;
// - dist/site/index.html : page complète pour l'hébergement statique (Netlify) et l'aperçu local.
import * as esbuild from 'esbuild';
import fs from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const watch = process.argv.includes('--watch');
const out = path.join(root, 'dist/cartographe-attack.html');
const site = path.join(root, 'dist/site/index.html');
const DESCRIPTION = 'Triage SOC dans le navigateur : logs → techniques MITRE ATT&CK → contre-mesures D3FEND, avec une fiche par niveau (N1, N2, N3, responsable) et les règles Sigma.';

async function assemble(js) {
  const [tpl, css] = await Promise.all([
    fs.readFile(path.join(root, 'src/index.html'), 'utf8'),
    fs.readFile(path.join(root, 'src/styles.css'), 'utf8'),
  ]);
  // Fonctions de remplacement : un « $ » dans le JS ou le CSS ne doit pas être interprété.
  const html = tpl.replace('/*__STYLE__*/', () => css.trim()).replace('/*__SCRIPT__*/', () => js.replace(/<\/script/gi, '<\\/script'));
  await fs.mkdir(path.dirname(out), { recursive: true });
  await fs.writeFile(out, html);
  await fs.mkdir(path.dirname(site), { recursive: true });
  await fs.writeFile(site, `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="${DESCRIPTION}">
<meta property="og:type" content="website">
<meta property="og:title" content="Cartographe ATT&amp;CK">
<meta property="og:description" content="${DESCRIPTION}">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%232c5bd6'/%3E%3Cpath d='M8 22 16 8l8 14z' fill='none' stroke='white' stroke-width='3' stroke-linejoin='round'/%3E%3C/svg%3E">
</head>
<body>
${html}</body>
</html>
`);
  console.log(`${path.relative(root, out)} · ${(html.length / 1024).toFixed(0)} Ko (+ ${path.relative(root, site)})`);
}

const options = {
  entryPoints: [path.join(root, 'src/ui.js')],
  bundle: true,
  format: 'iife',
  target: 'es2022',
  minify: !watch,
  write: false,
  loader: { '.log': 'text', '.yml': 'text' },
  plugins: [{
    name: 'assemble',
    setup(build) {
      build.onEnd(async r => { if (!r.errors.length) await assemble(r.outputFiles[0].text); });
    },
  }],
};

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log('Surveillance de src/, rules/ (dont sigma.yml) et samples/demo.log…');
} else {
  await esbuild.build(options);
}
