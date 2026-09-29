// Construit dist/cartographe-attack.html : une page unique (CSS + JS inline) publiable comme Artifact.
import * as esbuild from 'esbuild';
import fs from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const watch = process.argv.includes('--watch');
const out = path.join(root, 'dist/cartographe-attack.html');
const preview = path.join(root, 'dist/preview.html');

async function assemble(js) {
  const [tpl, css] = await Promise.all([
    fs.readFile(path.join(root, 'src/index.html'), 'utf8'),
    fs.readFile(path.join(root, 'src/styles.css'), 'utf8'),
  ]);
  // Fonctions de remplacement : un « $ » dans le JS ou le CSS ne doit pas être interprété.
  const html = tpl.replace('/*__STYLE__*/', () => css.trim()).replace('/*__SCRIPT__*/', () => js.replace(/<\/script/gi, '<\\/script'));
  await fs.mkdir(path.dirname(out), { recursive: true });
  await fs.writeFile(out, html);
  // Aperçu local : l'Artifact ajoute lui-même doctype, <head> et <body> à la publication.
  await fs.writeFile(preview, `<!doctype html>\n<html lang="fr">\n<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">\n</head>\n<body>\n${html}</body>\n</html>\n`);
  console.log(`${path.relative(root, out)} · ${(html.length / 1024).toFixed(0)} Ko (+ ${path.relative(root, preview)})`);
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
