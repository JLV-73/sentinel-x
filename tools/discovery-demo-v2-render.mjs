import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { adaptDiscoveryLab } from '../frontend/src/discoveryLabAdapter.ts';
import { renderDiscoveryReport } from '../frontend/src/discoveryReport.ts';

const dir = resolve(process.argv[2]);
for (const scenario of ['standard', 'csp-resource']) {
  const input = JSON.parse(readFileSync(resolve(dir, `${scenario}.json`), 'utf8'));
  const report = adaptDiscoveryLab(input);
  for (const lang of ['fr','en']) {
    const html = renderDiscoveryReport(report, lang);
    if (/<script\b|onerror\s*=|SECRET_EXAMPLE|SECRET_DEMO|route-[a-f0-9]{64}/i.test(html)) throw new Error('unsafe output');
    writeFileSync(resolve(dir, `${scenario}-${lang}.html`), html, {flag:'wx'});
  }
  const bad = {...input, html:'<img src=x onerror=alert(1)>SECRET_DEMO'};
  let rejected = false;
  try { adaptDiscoveryLab(bad); } catch { rejected = true; }
  if (!rejected) throw new Error('injection not rejected');
}
console.log('Both source JSON fixtures projected with current adapter and renderer; injection rejected.');
