import {validatePartialHeaders, type PartialHeaders} from './discoveryPartialHeaders';
/** Standalone discovery report: structured, allowlisted facts only. No raw URLs,
 * HTTP bodies, headers, cookie values, exception text or arbitrary prose.
 * Route segments are controlled vocabulary, not a lossless URL representation.
 * Callers must map sensitive/dynamic segments to `segment` or `id` upstream.
 * Provenance is a caller declaration, not independent attestation. */
import {isSanitizedPath} from './discoverySafePath';
export type RouteSegment = 'home' | 'login' | 'account' | 'admin' | 'api' | 'users' | 'products' | 'search' | 'segment' | 'id';
export type PageState = 'completed' | 'redirected' | 'blocked' | 'failed' | 'not_visited' | 'indeterminate';
export type Observation = Readonly<{ kind: 'response'; state: 'observed' | 'indeterminate' | 'not_checked'; evidence: 'http_status' | null }>;
export type DiscoveryPage = Readonly<{ route: readonly RouteSegment[]; label?: string; sanitizedPath?: string; partial_headers?: PartialHeaders; depth: number | null; status: number | null; state: PageState; observations: readonly Observation[] }>;
/** Closed, sanitized projection of B; page is a zero-based reference into pages.
 * Caller must map B's positional page label to the effective page, copy only
 * the enumerated facts, map complete to analyzed and preserve other states.
 * details maps B cookies count/secure/httponly/samesite and prefix violations.
 * Findings retain engine tokens, not raw headers, paths or cookie values.
 * Redirects and HTTP errors have no analysis in B: map them to not_checked. */
export type PassiveFinding = Readonly<{
  rule_id: 'hsts.header_absent.v1' | 'hsts.disabled.v1' | 'csp.active_inline.v1' | 'csp.report_only_inline.v1' | 'cookie.syntax_indeterminate.v1' | 'cookie.missing_secure.v1' | 'cookie.missing_httponly.v1' | 'cookie.prefix_requirements.v1';
  qualification: 'confirmed' | 'investigate'; priority: 'unclassified';
  evidence: 'absent' | 'disabled' | 'default-src' | 'script-src' | 'script-src-elem' | 'script-src-attr' | 'style-src' | 'style-src-elem' | 'style-src-attr' | 'syntax_indeterminate' | 'attribute_missing_on_some' | 'prefix_requirements_not_met';
  recommendation: 'review_hsts_for_route' | 'review_inline_in_context' | 'review_policy_semantics' | 'review_cookie_syntax_in_context' | 'review_cookie_attributes_in_context' | 'review_cookie_prefix_in_context';
  limit: 'response_headers_only' | 'effect_not_determined' | 'acceptance_and_usage_unknown';
}>;
export type PassiveDetails = Readonly<{ x_content_type_options: 'present' | 'absent' | 'indeterminate'; referrer_policy: 'present' | 'absent' | 'indeterminate'; permissions_policy: 'present' | 'absent' | 'indeterminate'; cookie_count: number; secure_count: number | null; httponly_count: number | null; samesite_count: number | null; prefix_violations: number | null }>;
export type CspProjection = Readonly<{ directives: readonly Readonly<{ directive: string; unsafe_inline: boolean }>[]; effective: readonly Readonly<{ sink: string; directive: string; mode: string }>[] }>;
export type PassiveSecurity = Readonly<{ page: number; state: 'analyzed' | 'incomplete' | 'access_denied' | 'not_checked'; hsts: 'absent' | 'disabled' | 'positive' | 'indeterminate' | 'not_evaluated'; csp: 'absent' | 'present' | 'indeterminate' | 'not_evaluated'; csp_report_only: 'absent' | 'present' | 'indeterminate' | 'not_evaluated'; cookies: 'observed' | 'none_observed' | 'indeterminate' | 'not_evaluated'; findings: readonly PassiveFinding[]; details?: PassiveDetails; csp_projection?: Readonly<{ active: CspProjection; report_only: CspProjection }> }>;
export type DiscoveryReport = Readonly<{
  provenance: 'synthetic' | 'imported' | 'declared_observation' | 'lab';
  completeness: 'complete' | 'incomplete';
  limits: readonly ('restricted_access' | 'scope' | 'budget' | 'transport' | 'unknown')[];
  pages: readonly DiscoveryPage[];
  relations: readonly Readonly<{ from: number; to: number; kind: 'link' | 'redirect' }>[];
  resources: readonly Readonly<{ page: number; kind: 'script' | 'stylesheet' | 'image' | 'other' | 'form' | 'api'; count: number }>[];
  security?: readonly PassiveSecurity[];
  crawl?: Readonly<{ pages: number; requests: number; bytes: number; complete: boolean; reason: 'none' | 'unknown' | 'scope_blocked' | 'request_limit' | 'duration_limit' | 'byte_limit' | 'redirect_blocked' | 'redirect_loop' | 'page_limit' | 'depth_limit' | 'http_refused' | 'incomplete' | 'transport_error' }>;
}>;
export type ReportLanguage = 'fr' | 'en';

const crawlReasons: Record<ReportLanguage, Record<NonNullable<DiscoveryReport['crawl']>['reason'], string>> = {
  fr: { none: 'Aucune', unknown: 'Indéterminée', scope_blocked: 'Périmètre bloqué', request_limit: 'Limite de requêtes atteinte', duration_limit: 'Limite de durée atteinte', byte_limit: 'Limite de données atteinte', redirect_blocked: 'Redirection bloquée', redirect_loop: 'Boucle de redirection', page_limit: 'Limite de pages atteinte', depth_limit: 'Limite de profondeur atteinte', http_refused: 'Réponse HTTP non favorable', incomplete: 'Réponse incomplète', transport_error: 'Erreur de transport' },
  en: { none: 'None', unknown: 'Unknown', scope_blocked: 'Scope blocked', request_limit: 'Request limit reached', duration_limit: 'Duration limit reached', byte_limit: 'Data limit reached', redirect_blocked: 'Redirect blocked', redirect_loop: 'Redirect loop', page_limit: 'Page limit reached', depth_limit: 'Depth limit reached', http_refused: 'Unfavourable HTTP response', incomplete: 'Incomplete response', transport_error: 'Transport error' },
};

const routeTokens = ['home', 'login', 'account', 'admin', 'api', 'users', 'products', 'search', 'segment', 'id'] as const;
const labels = {
  fr: { title: 'Cartographie de découverte', intro: 'Observations structurées — aucune conclusion de sécurité déduite.', coverage: 'Couverture', pages: 'Pages', done: 'terminées', complete: 'Complet', incomplete: 'Incomplet', indeterminate: 'Indéterminé', completed: 'Terminée', blocked: 'Bloquée', failed: 'Échec', not_visited: 'Non visitée', observed: 'Observé', not_checked: 'Non vérifié', status: 'Statut HTTP', depth: 'Profondeur', observations: 'Observations par page', response: 'Réponse HTTP', evidence: 'Preuve', http_status: 'Statut HTTP rapporté', none: 'Aucune', relations: 'Relations', resources: 'Ressources', link: 'Lien', redirect: 'Redirection', script: 'Script', stylesheet: 'Feuille de style', image: 'Image', other: 'Autre', provenance: 'Provenance déclarée', lab: 'Laboratoire local — aucun site public observé', synthetic: 'Données synthétiques — aucune observation réelle', imported: 'Import déclaré — non attesté', declared_observation: 'Observation déclarée — non attestée', limits: 'Limites', restricted_access: 'Accès restreint', scope: 'Périmètre limité', budget: 'Budget limité', transport: 'Transport incomplet ou indisponible', unknown: 'Limite indéterminée', limitations: 'La couverture compte les pages terminées parmi les pages déclarées, pas toutes les pages existantes. Les routes sont des représentations assainies et peuvent masquer des segments. Les comptes et états sont déclarés ; une réponse 403 ne démontre pas une vulnérabilité. Ce rapport ne vérifie pas la provenance ni la sécurité de la cible.', empty: 'Aucune donnée', unit: 'élément(s)' },
  en: { title: 'Discovery map', intro: 'Structured observations — no security conclusion inferred.', coverage: 'Coverage', pages: 'Pages', done: 'completed', complete: 'Complete', incomplete: 'Incomplete', indeterminate: 'Indeterminate', completed: 'Completed', blocked: 'Blocked', failed: 'Failed', not_visited: 'Not visited', observed: 'Observed', not_checked: 'Not checked', status: 'HTTP status', depth: 'Depth', observations: 'Observations by page', response: 'HTTP response', evidence: 'Evidence', http_status: 'Reported HTTP status', none: 'None', relations: 'Relations', resources: 'Resources', link: 'Link', redirect: 'Redirect', script: 'Script', stylesheet: 'Stylesheet', image: 'Image', other: 'Other', provenance: 'Declared provenance', lab: 'Local laboratory — no public site observed', synthetic: 'Synthetic data — no real observation', imported: 'Declared import — not attested', declared_observation: 'Declared observation — not attested', limits: 'Limitations', restricted_access: 'Restricted access', scope: 'Limited scope', budget: 'Limited budget', transport: 'Incomplete or unavailable transport', unknown: 'Unknown limitation', limitations: 'Coverage counts completed pages among declared pages, not all existing pages. Routes are sanitized representations and may hide segments. Counts and states are declared; a 403 response does not demonstrate a vulnerability. This report does not verify provenance or target security.', empty: 'No data', unit: 'item(s)' },
} as const;

const escapeHtml = (value: unknown): string => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
function invalid(): never { throw new TypeError('Invalid discovery report'); }
function record(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) invalid();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(k => typeof k !== 'string' || !keys.includes(k))) invalid();
  for (const k of keys) { const descriptor = Object.getOwnPropertyDescriptor(value, k); if (!descriptor || !('value' in descriptor)) invalid(); }
}
function member(value: unknown, allowed: readonly string[]): void { if (typeof value !== 'string' || !allowed.includes(value)) invalid(); }
function list(value: unknown, max: number): asserts value is unknown[] { if (!Array.isArray(value) || value.length > max) invalid(); }
function integer(value: unknown, min: number, max: number): void { if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) invalid(); }
const cspNames = ['default-src','script-src','script-src-elem','script-src-attr','style-src','style-src-elem','style-src-attr','img-src','connect-src','font-src','frame-src','object-src','base-uri','form-action','frame-ancestors'];
function validateCsp(value: unknown, state: unknown): void {
  record(value, ['directives','effective']); list(value.directives, 15); list(value.effective, 4);
  if (state !== 'present' && (value.directives.length || value.effective.length)) invalid();
  const names = new Map<string, boolean>();
  for (const d of value.directives) { record(d,['directive','unsafe_inline']); member(d.directive,cspNames); if (typeof d.unsafe_inline !== 'boolean' || names.has(d.directive as string)) invalid(); names.set(d.directive as string,d.unsafe_inline as boolean); }
  const sinks = new Set<string>(), modes = new Map<string,string>();
  for (const item of value.effective) {
    record(item,['sink','directive','mode']); member(item.sink,['script-elem','script-attr','style-elem','style-attr']); member(item.mode,['review','uncertain']);
    const sink = item.sink as string; if (sinks.has(sink)) invalid(); sinks.add(sink);
    const [kind,suffix] = sink.split('-'); const applicable = [`${kind}-src-${suffix}`,`${kind}-src`,'default-src'].find(n=>names.has(n));
    if (!applicable || item.directive !== applicable || !names.get(applicable) || (modes.has(applicable) && modes.get(applicable) !== item.mode)) invalid();
    modes.set(applicable,item.mode as string);
  }
  for (const kind of ['script','style']) for (const suffix of ['elem','attr']) { const n = [`${kind}-src-${suffix}`,`${kind}-src`,'default-src'].find(x=>names.has(x)); if (n && names.get(n) && !sinks.has(`${kind}-${suffix}`)) invalid(); }
}
const findingRules: Record<string, readonly [string, readonly string[], readonly string[], string]> = {
  'hsts.header_absent.v1': ['confirmed', ['absent'], ['review_hsts_for_route'], 'response_headers_only'],
  'hsts.disabled.v1': ['confirmed', ['disabled'], ['review_hsts_for_route'], 'response_headers_only'],
  'csp.active_inline.v1': ['investigate', ['default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr'], ['review_inline_in_context', 'review_policy_semantics'], 'effect_not_determined'],
  'csp.report_only_inline.v1': ['investigate', ['default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr'], ['review_inline_in_context', 'review_policy_semantics'], 'effect_not_determined'],
  'cookie.syntax_indeterminate.v1': ['investigate', ['syntax_indeterminate'], ['review_cookie_syntax_in_context'], 'acceptance_and_usage_unknown'],
  'cookie.missing_secure.v1': ['investigate', ['attribute_missing_on_some'], ['review_cookie_attributes_in_context'], 'acceptance_and_usage_unknown'],
  'cookie.missing_httponly.v1': ['investigate', ['attribute_missing_on_some'], ['review_cookie_attributes_in_context'], 'acceptance_and_usage_unknown'],
  'cookie.prefix_requirements.v1': ['investigate', ['prefix_requirements_not_met'], ['review_cookie_prefix_in_context'], 'acceptance_and_usage_unknown'],
};
const securityText = {
  fr: { title: 'Analyse passive déclarée', empty: 'Analyse passive non fournie ou non vérifiée', analyzed: 'Analysée', incomplete: 'Réponse partielle — non analysée', access_denied: 'Accès refusé (403) — non analysé', not_checked: 'Non vérifiée', absent: 'Absent', disabled: 'Désactivé', positive: 'Durée positive', present: 'Présent', indeterminate: 'Indéterminé', not_evaluated: 'Non évalué', observed: 'Observés', none_observed: 'Aucun observé', confirmed: 'Fait confirmé par la règle, pas une vulnérabilité', investigate: 'À examiner', unclassified: 'Priorité non classée', response_headers_only: 'En-têtes de réponse uniquement', effect_not_determined: 'Effet non déterminé', acceptance_and_usage_unknown: 'Acceptation et usage inconnus', review_hsts_for_route: 'Revoir HSTS pour cette page', review_inline_in_context: 'Examiner les sources inline dans leur contexte', review_policy_semantics: 'Examiner la sémantique de la politique', review_cookie_syntax_in_context: 'Examiner la syntaxe des cookies en contexte', review_cookie_attributes_in_context: 'Examiner les attributs des cookies en contexte', review_cookie_prefix_in_context: 'Examiner les préfixes des cookies en contexte', note: 'Données et provenance déclarées, non attestées. Les constats décrivent une réponse et ne concluent ni à une vulnérabilité ni à la conformité. Méthode inconnue.', recommendation: 'Recommandation', reference: 'Référence de règle' },
  en: { title: 'Declared passive analysis', empty: 'Passive analysis not supplied or not checked', analyzed: 'Analyzed', incomplete: 'Partial response — not analyzed', access_denied: 'Access denied (403) — not analyzed', not_checked: 'Not checked', absent: 'Absent', disabled: 'Disabled', positive: 'Positive duration', present: 'Present', indeterminate: 'Indeterminate', not_evaluated: 'Not evaluated', observed: 'Observed', none_observed: 'None observed', confirmed: 'Fact confirmed by the rule, not a vulnerability', investigate: 'Investigate', unclassified: 'Priority unclassified', response_headers_only: 'Response headers only', effect_not_determined: 'Effect not determined', acceptance_and_usage_unknown: 'Acceptance and usage unknown', review_hsts_for_route: 'Review HSTS for this page', review_inline_in_context: 'Review inline sources in context', review_policy_semantics: 'Review policy semantics', review_cookie_syntax_in_context: 'Review cookie syntax in context', review_cookie_attributes_in_context: 'Review cookie attributes in context', review_cookie_prefix_in_context: 'Review cookie prefixes in context', note: 'Data and provenance are declared, not attested. Findings describe one response and do not establish a vulnerability or compliance. Method unknown.', recommendation: 'Recommendation', reference: 'Rule reference' },
} as const;
function validateSecurity(value: unknown, pages: readonly DiscoveryPage[]): void {
  list(value, 500); const seen = new Set<number>();
  for (const s of value) {
    record(s, ['page', 'state', 'hsts', 'csp', 'csp_report_only', 'cookies', 'findings', ...((s && typeof s === 'object' && Object.prototype.hasOwnProperty.call(s, 'details')) ? ['details'] : []), ...((s && typeof s === 'object' && Object.prototype.hasOwnProperty.call(s, 'csp_projection')) ? ['csp_projection'] : [])]);
    integer(s.page, 0, pages.length - 1); const page = pages[s.page as number];
    if (seen.has(s.page as number)) invalid(); seen.add(s.page as number);
    member(s.state, ['analyzed', 'incomplete', 'access_denied', 'not_checked']);
    member(s.hsts, ['absent', 'disabled', 'positive', 'indeterminate', 'not_evaluated']);
    for (const v of [s.csp, s.csp_report_only]) member(v, ['absent', 'present', 'indeterminate', 'not_evaluated']);
    member(s.cookies, ['observed', 'none_observed', 'indeterminate', 'not_evaluated']);
    list(s.findings, 100);
    if ('csp_projection' in s) { if (s.state !== 'analyzed') invalid(); record(s.csp_projection,['active','report_only']); validateCsp(s.csp_projection.active,s.csp); validateCsp(s.csp_projection.report_only,s.csp_report_only); }
    if ('details' in s) {
      if (s.state !== 'analyzed') invalid();
      const d = s.details; record(d, ['x_content_type_options', 'referrer_policy', 'permissions_policy', 'cookie_count', 'secure_count', 'httponly_count', 'samesite_count', 'prefix_violations']);
      for (const v of [d.x_content_type_options, d.referrer_policy, d.permissions_policy]) member(v, ['present', 'absent', 'indeterminate']);
      integer(d.cookie_count, 0, 256);
      if ((s.cookies === 'none_observed') !== (d.cookie_count === 0)) invalid();
      for (const v of [d.secure_count, d.httponly_count, d.samesite_count, d.prefix_violations]) {
        if (s.cookies === 'observed') integer(v, 0, d.cookie_count as number); else if (v !== null) invalid();
      }
    }
    if (s.state === 'analyzed') {
      if (page.state !== 'completed' || page.status === null || page.status < 200 || page.status >= 300 || [s.hsts, s.csp, s.csp_report_only, s.cookies].includes('not_evaluated')) invalid();
    } else {
      if ([s.hsts, s.csp, s.csp_report_only, s.cookies].some(x => x !== 'not_evaluated') || s.findings.length) invalid();
      if (s.state === 'access_denied' && (page.status !== 403 || page.state !== 'blocked')) invalid();
      if (s.state === 'incomplete' && page.state !== 'indeterminate') invalid();
    }
    const findingKeys = new Set<string>();
    for (const f of s.findings) {
      record(f, ['rule_id', 'qualification', 'priority', 'evidence', 'recommendation', 'limit']);
      if (typeof f.rule_id !== 'string' || !Object.hasOwn(findingRules, f.rule_id)) invalid();
      const rule = findingRules[f.rule_id as string];
      if (f.qualification !== rule[0] || f.priority !== 'unclassified' || f.limit !== rule[3]) invalid();
      member(f.evidence, rule[1]); member(f.recommendation, rule[2]);
      const key = `${f.rule_id}|${f.evidence}`; if (findingKeys.has(key)) invalid(); findingKeys.add(key);
      if ('details' in s) {
        const d = s.details as PassiveDetails;
        if (f.rule_id === 'cookie.missing_secure.v1' && d.secure_count === d.cookie_count || f.rule_id === 'cookie.missing_httponly.v1' && d.httponly_count === d.cookie_count || f.rule_id === 'cookie.prefix_requirements.v1' && d.prefix_violations === 0) invalid();
      }
      if ('csp_projection' in s && (f.rule_id === 'csp.active_inline.v1' || f.rule_id === 'csp.report_only_inline.v1')) {
        const projection = (s.csp_projection as { active: CspProjection; report_only: CspProjection })[f.rule_id === 'csp.active_inline.v1' ? 'active' : 'report_only'];
        if (!projection.effective.some(x => x.directive === f.evidence && (x.mode === 'review' ? 'review_inline_in_context' : 'review_policy_semantics') === f.recommendation)) invalid();
      }
      if (f.rule_id === 'hsts.header_absent.v1' && s.hsts !== 'absent' || f.rule_id === 'hsts.disabled.v1' && s.hsts !== 'disabled' || f.rule_id === 'csp.active_inline.v1' && s.csp !== 'present' || f.rule_id === 'csp.report_only_inline.v1' && s.csp_report_only !== 'present' || f.rule_id === 'cookie.syntax_indeterminate.v1' && s.cookies !== 'indeterminate' || (f.rule_id as string).startsWith('cookie.') && f.rule_id !== 'cookie.syntax_indeterminate.v1' && s.cookies !== 'observed') invalid();
    }
  }
}
function validate(input: unknown): asserts input is DiscoveryReport {
  record(input, ['provenance', 'completeness', 'limits', 'pages', 'relations', 'resources', ...((input && typeof input === 'object' && Object.prototype.hasOwnProperty.call(input, 'security')) ? ['security'] : []), ...((input && typeof input === 'object' && Object.prototype.hasOwnProperty.call(input, 'crawl')) ? ['crawl'] : [])]);
  member(input.provenance, ['synthetic', 'imported', 'declared_observation', 'lab']); member(input.completeness, ['complete', 'incomplete']);
  list(input.limits, 5); for (const limit of input.limits) member(limit, ['restricted_access', 'scope', 'budget', 'transport', 'unknown']);
  list(input.pages, 999); list(input.relations, 2000); list(input.resources, 2000);
  const pageLabels = new Set<string>();
  for (const page of input.pages) {
    record(page, ['route', 'depth', 'status', 'state', 'observations', ...((page && typeof page === 'object' && Object.hasOwn(page, 'label')) ? ['label'] : []), ...((page && typeof page === 'object' && Object.hasOwn(page, 'sanitizedPath')) ? ['sanitizedPath'] : []), ...((page && typeof page === 'object' && Object.hasOwn(page, 'partial_headers')) ? ['partial_headers'] : [])]); list(page.route, 20);
    if ('partial_headers' in page) { if (page.state !== 'indeterminate' || page.status === null) invalid(); validatePartialHeaders(page.partial_headers); }
    if ('sanitizedPath' in page && (!isSanitizedPath(page.sanitizedPath) || !('label' in page))) invalid();
    if ('label' in page) {
      if (typeof page.label !== 'string' || !/^page-[1-9][0-9]{0,2}(?![\s\S])$/.test(page.label) || pageLabels.has(page.label)) invalid();
      pageLabels.add(page.label);
    }
    for (const segment of page.route) member(segment, routeTokens);
    if (page.depth === null) { if (page.state !== 'not_visited') invalid(); } else integer(page.depth, 0, 100); if (page.status !== null) integer(page.status, 100, 599);
    member(page.state, ['completed', 'redirected', 'blocked', 'failed', 'not_visited', 'indeterminate']);
    if (page.state === 'redirected' && (page.status === null || (page.status as number) < 300 || (page.status as number) >= 400)) invalid();
    if (page.state === 'completed' && (page.status === null || (page.status as number) < 200 || (page.status as number) >= 300)) invalid();
    if (page.state === 'blocked' && page.status !== 403) invalid();
    if (page.state === 'failed' && (page.status === null || (page.status as number) < 400 || page.status === 403)) invalid();
    if (page.state === 'not_visited' && page.status !== null) invalid();
    list(page.observations, 50);
    for (const observation of page.observations) {
      record(observation, ['kind', 'state', 'evidence']); member(observation.kind, ['response']); member(observation.state, ['observed', 'indeterminate', 'not_checked']);
      if (observation.evidence !== null && observation.evidence !== 'http_status') invalid();
      if (observation.evidence === 'http_status' && page.status === null) invalid();
      if (observation.state === 'observed' && (observation.evidence !== 'http_status' || page.status === null)) invalid();
      if (observation.state === 'not_checked' && observation.evidence !== null) invalid();
    }
  }
  for (const relation of input.relations) { record(relation, ['from', 'to', 'kind']); integer(relation.from, 0, input.pages.length - 1); integer(relation.to, 0, input.pages.length - 1); member(relation.kind, ['link', 'redirect']); }
  for (const resource of input.resources) { record(resource, ['page', 'kind', 'count']); integer(resource.page, 0, input.pages.length - 1); integer(resource.count, 0, 1000000); member(resource.kind, ['script', 'stylesheet', 'image', 'other','form','api']); }
  if ('crawl' in input) { const c=input.crawl; record(c,['pages','requests','bytes','complete','reason']); integer(c.pages,0,100); integer(c.requests,0,30); integer(c.bytes,0,10485760 + 65536); if (typeof c.complete !== 'boolean') invalid(); member(c.reason,['none','unknown','scope_blocked','request_limit','duration_limit','byte_limit','redirect_blocked','redirect_loop','page_limit','depth_limit','http_refused','incomplete','transport_error']); if (c.complete !== (c.reason === 'none') || (c.pages as number) > (c.requests as number)) invalid(); }
  if ('security' in input) validateSecurity(input.security, input.pages as DiscoveryPage[]);
  if (input.completeness === 'complete' && (input.pages.length === 0 || input.limits.length !== 0 || input.pages.some(p => (p as DiscoveryPage).state !== 'completed'))) invalid();
}

/** Pure renderer. Throws a generic TypeError for an invalid/unsafe contract. */
export function renderDiscoveryReport(input: DiscoveryReport, language: ReportLanguage): string {
  validate(input); if (language !== 'fr' && language !== 'en') invalid();
  const t = labels[language]; const e = escapeHtml;
  const aliasNote = input.pages.some(p => p.sanitizedPath) ? (language === 'fr' ? 'Les identifiants page-N sont des alias ; les chemins structurels assainis ne sont pas des chemins exacts et peuvent être identiques pour plusieurs pages.' : 'Page-N identifiers are aliases; sanitized structural paths are not exact paths and may be identical for several pages.') : '';
  const route = (page: DiscoveryPage) => page.sanitizedPath ? `${page.label} — ${page.sanitizedPath}` : page.label ?? '/' + page.route.map(s => s === 'home' ? '' : s === 'segment' ? '{segment}' : s === 'id' ? '{id}' : s).filter(Boolean).join('/');
  const done = input.pages.filter(p => p.state === 'completed').length;
  const cards = input.pages.map((p, i) => `<article class="card"><div class="row"><h3>${e(route(p))}</h3><span class="badge">${e(p.state === 'redirected' ? (language === 'fr' ? 'Redirigée' : 'Redirected') : t[p.state])}</span></div><p>${e(t.depth)}: ${e(p.depth === null ? t.indeterminate : p.depth)} · ${e(t.status)}: ${e(p.status === null ? t.indeterminate : p.status)}</p><h4>${e(t.observations)}</h4>${p.observations.length ? `<ul>${p.observations.map(o => `<li>${e(t[o.kind])}: <strong>${e(t[o.state])}</strong> · ${e(t.evidence)}: ${e(o.evidence === null ? t.none : t[o.evidence])}${o.evidence === 'http_status' ? ` (${e(p.status)})` : ''}</li>`).join('')}</ul>` : `<p>${e(t.empty)}</p>`}${p.partial_headers ? `<p>${language === 'fr' ? 'Corps incomplet ; en-têtes validés présents (noms uniquement)' : 'Body incomplete; validated headers present (names only)'}: ${p.partial_headers.present.length ? p.partial_headers.present.map(e).join(', ') : (language === 'fr' ? 'aucun nom signalé' : 'no names reported')}</p>` : ''}<small>#${i + 1}</small></article>`).join('');
  const relationRows = input.relations.map(r => `<li>${e(route(input.pages[r.from]))} → ${e(route(input.pages[r.to]))} · ${e(t[r.kind])}</li>`).join('');
  const resourceRows = input.resources.map(r => `<li>${e(route(input.pages[r.page]))} · ${e(r.kind === 'form' ? (language === 'fr' ? 'Référence de formulaire' : 'Form reference') : r.kind === 'api' ? (language === 'fr' ? 'Référence API' : 'API reference') : t[r.kind])}: ${e(r.count)}</li>`).join('');
  const limits = input.limits.map(x => `<li>${e(t[x])}</li>`).join('');
  const st = securityText[language];
  const evidenceText: Record<string, readonly [string, string]> = {
    syntax_indeterminate: ['Syntaxe indéterminée', 'Syntax indeterminate'],
    attribute_missing_on_some: ['Attribut absent sur certains cookies', 'Attribute missing on some cookies'],
    prefix_requirements_not_met: ['Exigences de préfixe non satisfaites', 'Prefix requirements not met'],
  };
  const text = (key: string) => (st as Record<string, string>)[key] ?? evidenceText[key]?.[language === 'fr' ? 0 : 1] ?? key;
  const cspGroups = new Map<string, number[]>();
  for (const s of input.security ?? []) if (s.csp_projection) {
    const key = JSON.stringify([s.csp, s.csp_report_only, s.csp_projection]);
    const pages = cspGroups.get(key) ?? []; pages.push(s.page); cspGroups.set(key, pages);
  }
  const cspSummary = [...cspGroups.values()].filter(pages => pages.length > 1).map(pages => `<p>${e(pages.length)} ${language === 'fr' ? 'pages : même projection CSP' : 'pages: same CSP projection'} — ${pages.map(i => e(route(input.pages[i]))).join(' · ')}. ${language === 'fr' ? 'Projection partielle, pas identité des politiques complètes.' : 'Partial projection, not identity of complete policies.'}</p>`).join('');
  const securityCards = (input.security ?? []).map(s => {
    const d = s.details;
    const n = (value: number | null) => e(value === null ? text('not_evaluated') : value);
    const details = d ? `<p>X-Content-Type-Options: ${e(text(d.x_content_type_options))} · Referrer-Policy: ${e(text(d.referrer_policy))} · Permissions-Policy: ${e(text(d.permissions_policy))}</p><p>Cookies: ${n(d.cookie_count)} · Secure: ${n(d.secure_count)} · HttpOnly: ${n(d.httponly_count)} · SameSite: ${n(d.samesite_count)} · ${language === 'fr' ? 'Préfixes non conformes' : 'Prefix violations'}: ${n(d.prefix_violations)}</p>` : '';
    const csp = s.csp_projection ? (['active','report_only'] as const).map(k => `<p>CSP ${e(k)} — ${s.csp_projection![k].directives.map(d => `${e(d.directive)}: unsafe-inline ${d.unsafe_inline ? (language === 'fr' ? 'présent' : 'present') : (language === 'fr' ? 'absent' : 'absent')}`).join(' · ') || e(t.none)}</p>`).join('') : '';
    return `<article class="card"><h3>${e(route(input.pages[s.page]))}</h3><p>${e(text(s.state))}</p><p>HSTS: ${e(text(s.hsts))} · CSP: ${e(text(s.csp))} · CSP report-only: ${e(text(s.csp_report_only))} · Cookies: ${e(text(s.cookies))}</p>${details}${csp ? `<details><summary>${language === 'fr' ? 'Détails CSP par directive' : 'CSP directive details'}</summary>${csp}${(['active','report_only'] as const).map(k => s.csp_projection![k].effective.map(v => `<p>${e(k)} · ${e(v.sink)} → ${e(v.directive)} · ${e(v.mode)}</p>`).join('')).join('')}</details>` : ''}${s.findings.length ? `<p>${e(st.reference)}: ${s.findings.map(f=>e(f.rule_id)).join(' · ')}</p>` : ''}</article>`;
  }).join('');
  const crawl = input.crawl ? `<h2>${language === 'fr' ? 'Parcours déclaré' : 'Declared crawl'}</h2><section class="panel"><p>${language === 'fr' ? 'État du parcours' : 'Crawl status'}: ${e(input.crawl.complete ? t.complete : t.incomplete)} · ${language === 'fr' ? 'Cause' : 'Reason'}: ${e(crawlReasons[language][input.crawl.reason])}</p><p>${language === 'fr' ? 'Pages collectées' : 'Collected pages'}: ${e(input.crawl.pages)} · ${language === 'fr' ? 'Tentatives' : 'Attempts'}: ${e(input.crawl.requests)} · ${language === 'fr' ? 'Octets' : 'Bytes'}: ${e(input.crawl.bytes)}</p><p>${language === 'fr' ? 'La couverture technique et la projection demeurent limitées même si le parcours est terminé ; formulaires et API sont des références, non des requêtes.' : 'Technical coverage and projection remain limited even when the crawl is complete; forms and APIs are references, not requests.'}</p></section>` : '';
  const groups = new Map<string, {finding: PassiveFinding; pages: number[]}>();
  for (const s of input.security ?? []) for (const f of s.findings) {
    const key = [f.rule_id,f.qualification,f.priority,f.evidence,f.recommendation,f.limit].join('|'), existing = groups.get(key);
    if (existing) existing.pages.push(s.page); else groups.set(key, {finding:f, pages:[s.page]});
  }
  const rank = (id:string) => id.startsWith('hsts.') ? 0 : id.startsWith('csp.') ? 1 : 2;
  const recommendations = [...groups.values()].sort((a,b) => rank(a.finding.rule_id)-rank(b.finding.rule_id) || a.finding.rule_id.localeCompare(b.finding.rule_id) || a.finding.evidence.localeCompare(b.finding.evidence)).map(({finding:f,pages}) => `<section class="card"><h4>${e(f.rule_id)}</h4><p>${e(text(f.qualification))} · ${e(text(f.priority))}</p><p>${e(t.evidence)}: ${e(text(f.evidence))} · ${e(st.reference)}: ${e(f.rule_id)}</p><p>${e(st.recommendation)}: ${e(text(f.recommendation))} · ${e(text(f.limit))}</p><ul>${pages.map(i=>`<li>${e(route(input.pages[i]))}: ${e(text(f.evidence))}</li>`).join('')}</ul></section>`).join('');
  const bounded = input.crawl?.reason === 'page_limit' && input.pages.some(p=>p.status !== null) ? `<p>${language === 'fr' ? 'Collecte bornée : réponses reçues ; couverture partielle.' : 'Bounded collection: responses received; partial coverage.'}</p>` : '';
  const securitySection = `${crawl}${bounded}<h2>C · ${e(st.title)}</h2><section class="panel"><p>${e(st.note)}</p>${cspSummary}<div class="grid">${securityCards || `<p>${e(st.empty)}</p>`}</div></section><h2>D · ${language === 'fr' ? 'Recommandations' : 'Recommendations'}</h2><section class="panel">${recommendations || `<p>${e(st.empty)}</p>`}</section><h2>E · ${language === 'fr' ? 'Preuves et méthode' : 'Evidence and method'}</h2><section class="panel"><p>${e(st.note)}</p><p>${e(t.limitations)}</p></section>`;
  return `<!doctype html><html lang="${language}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${e(t.title)}</title><style> :root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#070c17;color:#e8f5ff;font:16px/1.55 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:clamp(20px,5vw,60px)}header{border-bottom:1px solid #23435a;padding-bottom:28px}h1{font-size:clamp(2rem,5vw,3.6rem);line-height:1.1;margin:.25em 0}h2{margin-top:2em;color:#9ceeff}h3{margin:0;overflow-wrap:anywhere}h4{margin-bottom:.4em}p,li{color:#c1d5e4}small{color:#98afbe}.eyebrow{letter-spacing:.16em;color:#53e0ef;font-size:.75rem;font-weight:700}.summary,.card,.panel{background:#0e1b2b;border:1px solid #23455a;border-radius:15px;padding:22px}.summary{margin-top:26px;display:flex;gap:30px;flex-wrap:wrap}.summary strong{font-size:1.3rem;color:#b5f8ff}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:16px}.row{display:flex;justify-content:space-between;gap:1rem;align-items:start}.badge{color:#8ff4ff;border:1px solid #287a8c;border-radius:99px;padding:3px 10px;white-space:nowrap;font-size:.8rem}ul{padding-left:1.2em}footer{margin-top:50px;color:#9ab5c4;font-size:.9rem}@media print{body{background:white;color:#111}p,li,small{color:#222}.summary,.card,.panel{background:white;border-color:#888}h2,.summary strong,.badge{color:#123}}</style></head><body><main><header><div class="eyebrow">JLV Labs / SENTINEL X — NIGHTFALL · DISCOVERY</div><h1>${e(t.title)}</h1><p>${e(t.intro)} ${e(aliasNote)}</p></header><h2>A · ${language === 'fr' ? 'Synthèse exécutive' : 'Executive summary'}</h2><section class="summary" aria-label="${e(t.coverage)}"><div>${e(t.coverage)}<br><strong>${e(done)} / ${e(input.pages.length)}</strong> ${e(t.done)}<br><small>${language === 'fr' ? 'pages terminées parmi les pages déclarées' : 'completed pages among declared pages'}</small></div><div>${language === 'fr' ? 'État de la projection des pages' : 'Page projection status'}<br><strong>${e(t[input.completeness])}</strong></div><div>${e(t.provenance)}<br><strong>${e(t[input.provenance])}</strong></div><div>${language === 'fr' ? 'Origine HTTPS : inconnue' : 'HTTPS origin: unknown'}</div><div>${language === 'fr' ? 'Pages avec analyse passive déclarée' : 'Pages with declared passive analysis'}: <strong>${e(input.security ? input.security.filter(s => s.state === 'analyzed').length : (language === 'fr' ? 'inconnu' : 'unknown'))}</strong></div><div>${language === 'fr' ? 'Constats déclarés' : 'Declared findings'}: <strong>${e(input.security ? input.security.reduce((n, s) => n + s.findings.length, 0) : (language === 'fr' ? 'inconnu' : 'unknown'))}</strong><br><small>${language === 'fr' ? 'Faits à contextualiser, sans verdict de vulnérabilité.' : 'Facts requiring context, not a vulnerability verdict.'}</small></div><div>${language === 'fr' ? 'Cause de fin du parcours' : 'Crawl stop reason'}: <strong>${e(input.crawl ? crawlReasons[language][input.crawl.reason] : (language === 'fr' ? 'inconnue' : 'unknown'))}</strong></div></section><h2>B · ${e(t.pages)}</h2><div class="grid">${cards || `<p>${e(t.empty)}</p>`}</div><h2>${e(t.relations)}</h2><section class="panel">${relationRows ? `<p>${e(input.relations.length)} ${language === 'fr' ? 'relations déclarées' : 'declared relations'}</p><details><summary>${language === 'fr' ? 'Voir les relations' : 'Show relations'}</summary><ul>${relationRows}</ul></details>` : e(t.empty)}</section><h2>${e(t.resources)}</h2><section class="panel">${resourceRows ? `<ul>${resourceRows}</ul>` : e(t.empty)}</section><h2>${e(t.limits)}</h2><section class="panel">${limits ? `<ul>${limits}</ul>` : `<p>${e(t.none)}</p>`}<p>${e(t.limitations)}</p></section>${securitySection}<footer>JLV Labs / SENTINEL X — NIGHTFALL · DISCOVERY</footer></main></body></html>`;
}
