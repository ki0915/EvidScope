#!/usr/bin/env node
// Threat-scenario CLI for the improvement plan's "채점 답안" track.
//   node scripts/threat-scenarios.mjs score                 rules+sequence baseline over the catalog (JSON to stdout)
//   node scripts/threat-scenarios.mjs build --out DIR        write each scenario's synthetic records for inspection/injection
// Flags: --rules F (default data/risk-rules/ai-agent-baseline.json), --catalog F (default data/threat-scenarios/v1/catalog.json).
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdirSync, writeFileSync} from 'node:fs';
import {loadRules, loadCatalog, buildScenarioEvents, scoreCatalog} from '../src/threat-scenarios.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const cmd = args[0];
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const rulesPath = opt('--rules', join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalogPath = opt('--catalog', join(root, 'data/threat-scenarios/v1/catalog.json'));

if (cmd === 'score') {
  console.log(JSON.stringify(scoreCatalog(loadCatalog(catalogPath), loadRules(rulesPath)), null, 2));
} else if (cmd === 'build') {
  const outDir = opt('--out', join(root, '.test-runs/threat-scenarios'));
  mkdirSync(outDir, {recursive: true});
  const catalog = loadCatalog(catalogPath);
  for (const s of catalog.scenarios) writeFileSync(join(outDir, `${s.id}.events.json`), JSON.stringify(buildScenarioEvents(s), null, 2));
  console.log(JSON.stringify({built: catalog.scenarios.length, outDir}, null, 2));
} else {
  console.error('usage: threat-scenarios.mjs score|build [--rules F] [--catalog F] [--out DIR]');
  process.exit(1);
}
