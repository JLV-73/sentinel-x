import { renderDiscoveryReport, type DiscoveryReport, type DiscoveryPage, type PassiveSecurity, type PassiveFinding, type RouteSegment } from './discoveryReport';

// A deliberately narrow, fail-closed adapter for the local laboratory output.
// Anonymous identifiers are correlation keys only: hashes are never exported.
const fail = (): never => { throw new TypeError('Unsupported discovery laboratory output'); };
const obj = (v: any, keys: string[]) => {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.getPrototypeOf(v) !== Object.prototype || Reflect.ownKeys(v).length !== keys.length || keys.some(k => !Object.getOwnPropertyDescriptor(v,k) || !('value' in Object.getOwnPropertyDescriptor(v,k)!)) || Object.keys(v).some(k => !keys.includes(k))) fail();
};
const arr = (v: any, max=2000): any[] => { if (!Array.isArray(v) || v.length > max) fail(); return v; };
const num = (v: any, max=10000000) => { if (!Number.isSafeInteger(v) || v < 0 || v > max) fail(); };
const one = (v: any, xs: any[]) => { if (!xs.includes(v)) fail(); };
const id = (v: any) => { if (typeof v !== 'string' || !/^(route-[0-9a-f]{64}|opaque-[1-9][0-9]*)$/.test(v)) fail(); };
const LIMITS = ['caller_declared_provenance','effective_route_declared_by_caller','response_headers_only','method_unknown','positional_route_labels','no_vulnerability_or_compliance_conclusion'];
const checkLimits = (x: any) => { if (JSON.stringify(x) !== JSON.stringify(LIMITS)) fail(); };

export function adaptDiscoveryLab(input: unknown): DiscoveryReport {
 const x: any = input;
 obj(x,['pages','requests','bytes','complete','reason','graph','intelligence']);
 num(x.pages,100); num(x.requests,30); num(x.bytes,10485760 + 65536); if (typeof x.complete !== 'boolean' || x.pages > x.requests) fail();
 one(x.reason,['none','unknown','request_limit','duration_limit','byte_limit','redirect_blocked','redirect_loop','page_limit','depth_limit','http_refused','incomplete']);
 if (x.complete !== (x.reason === 'none')) fail();
 obj(x.graph,['pages','relations','resources']); obj(x.intelligence,['schema_version','pages','limits']);
 if (x.intelligence.schema_version !== 'fortress.discovery-intelligence/1') fail(); checkLimits(x.intelligence.limits);
 const graph = arr(x.graph.pages,100), relations = arr(x.graph.relations), resources = arr(x.graph.resources), entries = arr(x.intelligence.pages,100);
 if (graph.length !== x.pages || entries.length > x.requests) fail();
 const ids: string[] = []; const depths = new Map<string,number>(); const statuses = new Map<string,number>();
 const add = (s: string) => { id(s); if (!ids.includes(s)) ids.push(s); };
 for (const p of graph) { obj(p,['route','depth','status']); add(p.route); num(p.depth,100); if ((p.status !== 200 && p.status !== 204) || depths.has(p.route)) fail(); depths.set(p.route,p.depth); statuses.set(p.route,p.status); }
 for (const [i,p] of entries.entries()) { obj(p,['route','observed_at','status','state','method','provenance','confidence','observations','findings','limits','graph_route']); add(p.graph_route); if (p.route !== `page-${i+1}` || typeof p.observed_at !== 'string' || !/^\d{4}-\d\d-\d\dT/.test(p.observed_at) || !Number.isFinite(Date.parse(p.observed_at)) || p.method !== 'unknown') fail(); obj(p.provenance,['kind','attestation']); if (p.provenance.kind !== 'caller_declared' || p.provenance.attestation !== 'none') fail(); checkLimits(p.limits); }
 if (new Set(entries.map(p=>p.graph_route)).size !== entries.length) fail();
 for (const r of relations) { obj(r,['from','to','kind']); add(r.from); add(r.to); one(r.kind,['link','redirect']); }
 for (const r of resources) { obj(r,['page','kind']); add(r.page); one(r.kind,['script','stylesheet','image','other','form','api']); }
 if (entries.length && !depths.has(entries[0].graph_route)) depths.set(entries[0].graph_route,0);
 // A redirect preserves crawl depth; links add one. Reject unresolved or conflicting attribution.
 for (let n=0;n<ids.length;n++) for (const r of relations) { const d=depths.get(r.from); if (d !== undefined && !depths.has(r.to)) depths.set(r.to,d+(r.kind==='link'?1:0)); }
 // Multiple links may point to a page already reached at a different depth; its
 // explicit graph depth wins. Redirect source must otherwise be resolvable.
 for (const s of ids) if (!depths.has(s)) fail();
 const index = (s:string) => ids.indexOf(s);
 const pages: DiscoveryPage[] = ids.map((s,i) => {
   const p = entries.find(e=>e.graph_route===s); const status = p?.status ?? null;
   if (p && status !== null) { num(status,599); if (status<200) fail(); }
   if (statuses.has(s) && status !== statuses.get(s)) fail();
   const state = !p ? 'not_visited' : p.state==='complete' ? 'completed' : p.state==='access_denied' ? 'blocked' : p.state==='redirected' ? 'indeterminate' : p.state==='incomplete' ? 'indeterminate' : p.state==='http_error' ? 'failed' : fail();
   if (p && ((p.state==='complete' && !(status>=200 && status<300)) || (p.state==='access_denied' && status!==403) || (p.state==='redirected' && !(status>=300 && status<400)) || (p.state==='http_error' && !(status>=400 && status!==403)) || (p.state==='incomplete' && status!==null))) fail();
   // Binary token path gives each opaque node a distinct renderer-safe alias,
   // without revealing or pretending to reconstruct original route segments.
   const route: RouteSegment[] = i===0 ? ['home'] : ['segment', ...i.toString(2).split('').map(c=>c==='0'?'segment' as const:'id' as const)];
   return {route,depth:depths.get(s)!,status,state,observations:[{kind:'response',state:status===null ? (p?'indeterminate':'not_checked') : 'observed',evidence:status===null?null:'http_status'}]};
 });
 const security: PassiveSecurity[] = entries.map(p=>{
   const page=index(p.graph_route); const findings: PassiveFinding[]=[];
   if (p.state !== 'complete') {
     if (p.observations!==null || arr(p.findings,100).length || p.confidence!=='not_evaluated') fail();
     return {page,state:p.state==='access_denied'?'access_denied':p.state==='incomplete'?'incomplete':'not_checked',hsts:'not_evaluated',csp:'not_evaluated',csp_report_only:'not_evaluated',cookies:'not_evaluated',findings};
   }
   if (p.confidence!=='caller_declared') fail(); const o=p.observations;
   obj(o,['http_status','hsts','csp','csp_report_only','csp_directives','csp_report_only_directives','csp_effective','csp_report_only_effective','cookie_prefix','x_content_type_options','referrer_policy','permissions_policy','cookies']);
   if (o.http_status!==p.status) fail();

   one(o.hsts,['absent','disabled','positive','indeterminate']); for (const v of [o.csp,o.csp_report_only]) one(v,['absent','present','indeterminate']);
   for (const k of ['x_content_type_options','referrer_policy','permissions_policy']) one(o[k],['absent','present','indeterminate']);
   obj(o.cookies,['state','count','secure','httponly','samesite']); obj(o.cookie_prefix,['state','violations']);
   one(o.cookies.state,['observed','none_observed','indeterminate']); one(o.cookie_prefix.state,['observed','none_observed','indeterminate']);
   num(o.cookies.count,256); if (o.cookie_prefix.state !== o.cookies.state || (o.cookies.state==='none_observed') !== (o.cookies.count===0)) fail();
   for (const k of ['secure','httponly','samesite']) { if (o.cookies.state==='observed') num(o.cookies[k],o.cookies.count); else if(o.cookies[k]!==null) fail(); }
   if(o.cookies.state==='observed') num(o.cookie_prefix.violations,o.cookies.count); else if(o.cookie_prefix.violations!==null) fail();
   for (const f of arr(p.findings,100)) { obj(f,['rule_id','qualification','priority','evidence','recommendation','limit','route','confidence','provenance']); if(f.route!==p.route || f.confidence!=='caller_declared' || f.provenance!=='response_headers') fail(); findings.push({rule_id:f.rule_id,qualification:f.qualification,priority:f.priority,evidence:f.evidence,recommendation:f.recommendation,limit:f.limit}); }
   return {page,state:'analyzed',hsts:o.hsts,csp:o.csp,csp_report_only:o.csp_report_only,cookies:o.cookies.state,findings,csp_projection:{active:{directives:o.csp_directives,effective:o.csp_effective},report_only:{directives:o.csp_report_only_directives,effective:o.csp_report_only_effective}},details:{x_content_type_options:o.x_content_type_options,referrer_policy:o.referrer_policy,permissions_policy:o.permissions_policy,cookie_count:o.cookies.count,secure_count:o.cookies.secure,httponly_count:o.cookies.httponly,samesite_count:o.cookies.samesite,prefix_violations:o.cookie_prefix.violations}};
 });
 const projectionComplete = x.complete && pages.length > 0 && pages.every(p=>p.state==='completed');
 const lim: DiscoveryReport['limits'] = [...new Set<NonNullable<DiscoveryReport['limits'][number]>>([...(projectionComplete?[]:['unknown' as const]),...(entries.some(p=>p.status===403)?['restricted_access' as const]:[]),...(['request_limit','page_limit','depth_limit','byte_limit','duration_limit'].includes(x.reason)?['budget' as const]:[]),...(['incomplete','redirect_blocked','redirect_loop'].includes(x.reason)?['transport' as const]:[])])];
 const report: DiscoveryReport = {provenance:'synthetic',completeness:projectionComplete?'complete':'incomplete',crawl:{pages:x.pages,requests:x.requests,bytes:x.bytes,complete:x.complete,reason:x.reason},limits:lim,pages,relations:relations.map(r=>({from:index(r.from),to:index(r.to),kind:r.kind})),resources:resources.map(r=>({page:index(r.page),kind:r.kind,count:1})),security};
 // Reuse C's strict contract checks before returning the projection.
 renderDiscoveryReport(report,'fr');
 return report;
}
