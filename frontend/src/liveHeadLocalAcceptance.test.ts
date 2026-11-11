import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import { parseObservation, renderLiveReport } from './liveObservation';

const evidencePath = process.env.SENTINEL_HEAD_LAB_EVIDENCE;
const fixture = evidencePath ? JSON.parse(readFileSync(evidencePath, 'utf8')) : null;
describe.skipIf(!fixture)('local TLS HEAD supervised observation rendering', () => {
  it('renders actual observations and timeout without exposing fixture cookie', () => {
    for (const lang of ['fr', 'en'] as const) {
      const first = renderLiveReport(parseObservation(fixture.first, fixture.first.target), lang);
      const second = renderLiveReport(parseObservation(fixture.second, fixture.second.target), lang);
      const timeout = renderLiveReport(parseObservation(fixture.timeout, fixture.timeout.target), lang);
      for (const html of [first, second, timeout]) {
        expect(html).toContain('HEAD');
        expect(html).not.toContain('synthetic_hidden_value');
        expect(html).not.toContain('labtoken');
      }
      expect(first).toContain('csp.active_inline.v1');
      expect(second).toContain('hsts.disabled.v1');
      expect(first).not.toContain('hsts.disabled.v1');
      expect(timeout).toContain(lang === 'fr' ? 'Délai dépassé' : 'Timed out');
      expect(timeout).not.toContain('hsts.disabled.v1');
    }
  });
});
