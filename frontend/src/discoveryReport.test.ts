import assert from 'node:assert/strict';
// Run under the candidate's Vitest when installed, or Node's built-in runner.
const { test } = (process.env.VITEST ? await import('vitest') : await import('node:test')) as { test: typeof import('vitest').test };
const modulePath = './discoveryReport.ts';
const { renderDiscoveryReport } = await import(modulePath);

test('rend un rapport autonome multilingue sans conclusion de vulnérabilité pour 403', () => {
  const report = {
    provenance: 'synthetic', completeness: 'incomplete', limits: ['restricted_access'],
    pages: [
      { route: ['home'], depth: 0, status: 200, state: 'completed', observations: [{ kind: 'response', state: 'observed', evidence: 'http_status' }] },
      { route: ['login'], depth: 1, status: 403, state: 'blocked', observations: [{ kind: 'response', state: 'indeterminate', evidence: 'http_status' }] },
    ], relations: [{ from: 0, to: 1, kind: 'link' }], resources: [{ page: 0, kind: 'script', count: 2 }],
  } as const;
  const fr = renderDiscoveryReport(report, 'fr');
  const en = renderDiscoveryReport(report, 'en');
  assert.match(fr, /<!doctype html>/i);
  assert.match(fr, /Incomplet/); assert.match(fr, /Indéterminé/); assert.match(fr, /403/);
  assert.match(en, /Incomplete/); assert.match(en, /Indeterminate/); assert.match(en, /403/);
  assert.match(fr, /\/login/); assert.match(en, /\/login/);
  assert.doesNotMatch(fr, /vulnérabilité confirmée/i);
  assert.doesNotMatch(en, /confirmed vulnerability/i);
  assert.match(fr, /2<\/li>/); assert.match(fr, /Lien/); assert.match(en, /Link/);
  assert.match(fr, /1 \/ 2/); assert.match(fr, /synthétiques/);
});

const base = () => ({ provenance: 'imported', completeness: 'incomplete', limits: ['unknown'], pages: [{ route: ['api', 'id'], depth: 1, status: null, state: 'indeterminate', observations: [{ kind: 'response', state: 'indeterminate', evidence: null }] }], relations: [], resources: [] });

test('traduit chaque motif de parcours sans exposer son code interne', () => {
  const reasons = {
    none: ['Aucune', 'None'], unknown: ['Indéterminée', 'Unknown'],
    request_limit: ['Limite de requêtes atteinte', 'Request limit reached'],
    duration_limit: ['Limite de durée atteinte', 'Duration limit reached'],
    byte_limit: ['Limite de données atteinte', 'Data limit reached'],
    redirect_blocked: ['Redirection bloquée', 'Redirect blocked'],
    redirect_loop: ['Boucle de redirection', 'Redirect loop'],
    page_limit: ['Limite de pages atteinte', 'Page limit reached'],
    depth_limit: ['Limite de profondeur atteinte', 'Depth limit reached'],
    http_refused: ['Réponse HTTP non favorable', 'Unfavourable HTTP response'],
    incomplete: ['Réponse incomplète', 'Incomplete response'],
    transport_error: ['Erreur de transport', 'Transport error'],
  };
  for (const [reason, [fr, en]] of Object.entries(reasons)) {
    const report = { ...base(), crawl: { pages: 0, requests: 1, bytes: 0, complete: reason === 'none', reason } };
    for (const [language, label] of [['fr', fr], ['en', en]]) {
      const html = renderDiscoveryReport(report, language);
      assert.ok(html.includes(`${language === 'fr' ? 'Cause' : 'Reason'}: ${label}`), `${language}: ${reason}`);
      assert.ok(!html.includes(`: ${reason}</p>`), `${language}: ${reason}`);
    }
  }
});

test('refuse les alias dupliqués et un chemin structurel sans alias', () => {
  const page = { ...base().pages[0], label: 'page-1', sanitizedPath: '/{segment}/{segment}' };
  assert.throws(() => renderDiscoveryReport({ ...base(), pages: [page, page] }, 'fr'));
  const { label, ...unlabelled } = page;
  assert.throws(() => renderDiscoveryReport({ ...base(), pages: [unlabelled] }, 'en'));
});

test('explique les alias et les chemins structurels dans le rapport autonome', () => {
  const report = { ...base(), pages: [{ ...base().pages[0], label: 'page-1', sanitizedPath: '/{segment}/{segment}' }] };
  assert.match(renderDiscoveryReport(report, 'fr'), /alias.*chemins exacts/i);
  assert.match(renderDiscoveryReport(report, 'en'), /aliases.*exact paths/i);
});

test('statut et preuve inconnus restent indéterminés en FR et EN', () => {
  const fr = renderDiscoveryReport(base(), 'fr'); const en = renderDiscoveryReport(base(), 'en');
  assert.match(fr, /Statut HTTP: Indéterminé/); assert.match(en, /HTTP status: Indeterminate/);
  assert.match(fr, /Preuve: Aucune/); assert.match(en, /Evidence: None/);
  assert.match(fr, /\/api\/\{id\}/); assert.doesNotMatch(fr, /NaN|undefined/);
});

test('rejette XSS, texte secret et clés supplémentaires à chaque niveau', () => {
  const bad = '<img src=x onerror=alert(1)>SECRET_TEST';
  const samples = [
    { ...base(), provenance: bad },
    { ...base(), limits: [bad] },
    { ...base(), secret: bad },
    { ...base(), pages: [{ ...base().pages[0], route: [bad] }] },
    { ...base(), pages: [{ ...base().pages[0], route: ['api?token=SECRET_TEST'] }] },
    { ...base(), pages: [{ ...base().pages[0], body: bad }] },
    { ...base(), pages: [{ ...base().pages[0], observations: [{ kind: 'response', state: 'indeterminate', evidence: null, raw: bad }] }] },
    { ...base(), relations: [{ from: 0, to: 0, kind: bad }] },
    { ...base(), resources: [{ page: 0, kind: 'script', count: 1, url: bad }] },
  ];
  for (const input of samples) assert.throws(() => renderDiscoveryReport(input, 'fr'), { name: 'TypeError', message: 'Invalid discovery report' });
  const html = renderDiscoveryReport(base(), 'fr');
  assert.doesNotMatch(html, /SECRET_TEST|<script|onerror=|https?:\/\//i);
  assert.match(html, /default-src 'none'/);
});

test('rejette preuve sans statut, indices inexistants et couverture contradictoire', () => {
  assert.throws(() => renderDiscoveryReport({ ...base(), pages: [{ ...base().pages[0], observations: [{ kind: 'response', state: 'observed', evidence: 'http_status' }] }] }, 'en'));
  assert.throws(() => renderDiscoveryReport({ ...base(), relations: [{ from: 0, to: 1, kind: 'link' }] }, 'en'));
  assert.throws(() => renderDiscoveryReport({ ...base(), completeness: 'complete' }, 'en'));
});


test('présente les constats passifs structurés et recommandations sans verdict', () => {
  const report = { ...base(), pages: [{ ...base().pages[0], status: 200, state: "completed" }], security: [{ page: 0, state: 'analyzed', hsts: 'absent', csp: 'present', csp_report_only: 'absent', cookies: 'observed', findings: [{ rule_id: 'hsts.header_absent.v1', qualification: 'confirmed', priority: 'unclassified', evidence: 'absent', recommendation: 'review_hsts_for_route', limit: 'response_headers_only' }] }] };
  const fr = renderDiscoveryReport(report, 'fr'); const en = renderDiscoveryReport(report, 'en');
  assert.match(fr, /HSTS/); assert.match(fr, /Revoir HSTS/); assert.match(en, /Review HSTS/);
  assert.match(fr, /hsts.header_absent.v1/); assert.match(fr, /Preuve/);
});


const projected = () => ({ ...base(), provenance: "synthetic", pages: [{ ...base().pages[0], status: 200, state: "completed" }], security: [{ page: 0, state: "analyzed", hsts: "disabled", csp: "present", csp_report_only: "present", cookies: "observed", findings: [
  { rule_id: "cookie.missing_httponly.v1", qualification: "investigate", priority: "unclassified", evidence: "attribute_missing_on_some", recommendation: "review_cookie_attributes_in_context", limit: "acceptance_and_usage_unknown" },
  { rule_id: "csp.report_only_inline.v1", qualification: "investigate", priority: "unclassified", evidence: "style-src", recommendation: "review_policy_semantics", limit: "effect_not_determined" },
  { rule_id: "hsts.disabled.v1", qualification: "confirmed", priority: "unclassified", evidence: "disabled", recommendation: "review_hsts_for_route", limit: "response_headers_only" },
  { rule_id: "csp.active_inline.v1", qualification: "investigate", priority: "unclassified", evidence: "script-src", recommendation: "review_inline_in_context", limit: "effect_not_determined" },
  { rule_id: "cookie.missing_secure.v1", qualification: "investigate", priority: "unclassified", evidence: "attribute_missing_on_some", recommendation: "review_cookie_attributes_in_context", limit: "acceptance_and_usage_unknown" },
  { rule_id: "cookie.prefix_requirements.v1", qualification: "investigate", priority: "unclassified", evidence: "prefix_requirements_not_met", recommendation: "review_cookie_prefix_in_context", limit: "acceptance_and_usage_unknown" },
] }] });

test("trie HSTS CSP cookies et présente les règles, preuves et limites", () => {
  for (const lang of ["fr", "en"]) {
    const html = renderDiscoveryReport(projected(), lang);
    const h = html.indexOf("<h4>hsts.disabled.v1"); const c = html.indexOf("<h4>csp.active_inline.v1"); const k = html.indexOf("<h4>cookie.missing_secure.v1");
    assert.ok(h >= 0 && h < c && c < k); assert.match(html, /script-src/); assert.match(html, /style-src/); assert.match(html, /cookie.prefix_requirements.v1/);
  }
});

test("distingue analyse absente, réponse partielle et 403", () => {
  assert.match(renderDiscoveryReport(base(), "fr"), /Analyse passive non fournie ou non vérifiée/);
  const empty = { page: 0, state: "incomplete", hsts: "not_evaluated", csp: "not_evaluated", csp_report_only: "not_evaluated", cookies: "not_evaluated", findings: [] };
  assert.match(renderDiscoveryReport({ ...base(), security: [empty] }, "fr"), /Réponse partielle — non analysée/);
  const denied = { ...base(), pages: [{ ...base().pages[0], status: 403, state: "blocked" }], security: [{ ...empty, state: "access_denied" }] };
  assert.match(renderDiscoveryReport(denied, "en"), /Access denied \(403\) — not analyzed/);
  assert.throws(() => renderDiscoveryReport({ ...denied, security: [{ ...empty, state: "analyzed" }] }, "en"));
});

test("syntaxe cookie indéterminée et absence de cookies ne deviennent pas des vulnérabilités", () => {
  const p = projected(); const s = p.security[0];
  const uncertain = { ...p, security: [{ ...s, cookies: "indeterminate", findings: [{ rule_id: "cookie.syntax_indeterminate.v1", qualification: "investigate", priority: "unclassified", evidence: "syntax_indeterminate", recommendation: "review_cookie_syntax_in_context", limit: "acceptance_and_usage_unknown" }] }] };
  assert.match(renderDiscoveryReport(uncertain, "en"), /Review cookie syntax in context/);
  assert.match(renderDiscoveryReport({ ...p, security: [{ ...s, cookies: "none_observed", findings: [] }] }, "en"), /None observed/);
});

test("rejette champs secrets, injection, liens erronés et constats contradictoires", () => {
  const p = projected(); const s = p.security[0]; const f = s.findings[0]; const evil = "<img onerror=alert(1)>SECRET_TEST";
  const items = [
    { ...p, security: [{ ...s, raw_headers: evil }] },
    { ...p, security: [{ ...s, findings: [{ ...f, evidence: evil }] }] },
    { ...p, security: [{ ...s, findings: [{ ...f, cookie_value: evil }] }] },
    { ...p, security: [{ ...s, findings: [{ ...f, rule_id: "__proto__" }] }] },
    { ...p, security: [{ ...s, findings: [{ ...f, recommendation: evil }] }] },
    { ...p, security: [{ ...s, page: 2 }] },
    { ...p, security: [s, s] },
    { ...p, security: [{ ...s, findings: [{ ...f, qualification: "confirmed" }] }] },
    { ...p, security: [{ ...s, cookies: "none_observed" }] },
  ];
  for (const item of items) assert.throws(() => renderDiscoveryReport(item, "fr"), { name: "TypeError", message: "Invalid discovery report" });
  assert.doesNotMatch(renderDiscoveryReport(p, "fr"), /SECRET_TEST|<script|onerror=/i);
});


test("affiche les autres observations B et les comptes de cookies sans valeurs brutes", () => {
  const p = projected(); const s = p.security[0];
  const details = { x_content_type_options: "present", referrer_policy: "absent", permissions_policy: "indeterminate", cookie_count: 2, secure_count: 1, httponly_count: 0, samesite_count: 2, prefix_violations: 1 };
  const html = renderDiscoveryReport({ ...p, security: [{ ...s, details }] }, "en");
  assert.match(html, /X-Content-Type-Options: Present/); assert.match(html, /SameSite: 2/); assert.match(html, /Prefix violations: 1/);
  assert.throws(() => renderDiscoveryReport({ ...p, security: [{ ...s, details: { ...details, cookie_value: "SECRET_TEST" } }] }, "en"));
  assert.throws(() => renderDiscoveryReport({ ...p, security: [{ ...s, details: { ...details, secure_count: 3 } }] }, "en"));
});


test("refuse les états contradictoires et constats dupliqués", () => {
  const p = projected(); const s = p.security[0];
  assert.throws(() => renderDiscoveryReport({ ...p, pages: [{ ...p.pages[0], state: "blocked" }] }, "fr"));
  assert.throws(() => renderDiscoveryReport({ ...p, security: [{ ...s, findings: [s.findings[0], s.findings[0]] }] }, "fr"));
});

test('refuse un constat cookie contredit par ses compteurs', () => {
  const p = projected(), s = p.security[0];
  const details = { x_content_type_options:'present', referrer_policy:'present', permissions_policy:'present', cookie_count:1, secure_count:1, httponly_count:1, samesite_count:1, prefix_violations:0 };
  assert.throws(() => renderDiscoveryReport({ ...p, security:[{...s,details}] },'en'));
});
