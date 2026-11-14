import { test, expect } from 'vitest';
import { adaptDiscoveryLab } from './discoveryLabAdapter';
import { renderDiscoveryReport } from './discoveryReport';
const limits = ['caller_declared_provenance','effective_route_declared_by_caller','response_headers_only','method_unknown','positional_route_labels','no_vulnerability_or_compliance_conclusion'];
const sample = () => ({pages:0,requests:1,bytes:100,complete:false,reason:'http_refused',graph:{pages:[],relations:[],resources:[]},intelligence:{schema_version:'fortress.discovery-intelligence/1',limits,pages:[{route:'page-1',observed_at:'2026-11-12T12:00:00+00:00',status:403,state:'access_denied',method:'unknown',provenance:{kind:'caller_declared',attestation:'none'},confidence:'not_evaluated',observations:null,findings:[],limits,graph_route:'route-'+ 'a'.repeat(64)}]}});
test('403 reste refusé et non analysé, sans fuite de hash', () => {
 const report = adaptDiscoveryLab(sample());
 expect(report.pages[0].status).toBe(403); expect(report.security?.[0].state).toBe('access_denied');
 const html = renderDiscoveryReport(report,'fr'); expect(html).toContain('403'); expect(html).not.toContain('a'.repeat(64));
});
test('la redirection reste observable et ne devient pas une analyse', () => {
 const x = sample(); const route = x.intelligence.pages[0].graph_route;
 x.intelligence.pages[0] = {...x.intelligence.pages[0], status:302, state:'redirected'};
 x.reason = 'redirect_blocked';
 const report = adaptDiscoveryLab(x);
 expect(report.pages[0].status).toBe(302); expect(report.pages[0].state).toBe('indeterminate');
 expect(report.security?.[0].state).toBe('not_checked'); expect(JSON.stringify(report)).not.toContain(route);
});
test('rejette données supplémentaires et identifiants contradictoires', () => {
 const x = sample(); expect(() => adaptDiscoveryLab({...x, html:'<script>secret</script>'})).toThrow();
 expect(() => adaptDiscoveryLab({...x,intelligence:{...x.intelligence,pages:[{...x.intelligence.pages[0],route:'page-2'}]}})).toThrow();
});


test('préserve le parcours et les références form/api', () => {
 const x = sample(); x.graph.resources = [{page:x.intelligence.pages[0].graph_route,kind:'form'},{page:x.intelligence.pages[0].graph_route,kind:'api'}] as never[];
 const report = adaptDiscoveryLab(x);
 expect(report.resources.map(r => r.kind)).toEqual(['form','api']);
 expect(report.crawl).toEqual({pages:0,requests:1,bytes:100,complete:false,reason:'http_refused'});
 expect(renderDiscoveryReport(report,'en')).toContain('Unfavourable HTTP response');
});


test('accepte CSP structurée et refuse contradictions sans exposer de valeur brute', () => {
 const x:any = sample(); const p = x.intelligence.pages[0];
 x.pages=1; x.graph.pages=[{route:p.graph_route,depth:0,status:200}]; x.reason='none'; x.complete=true;
 Object.assign(p,{status:200,state:'complete',confidence:'caller_declared',observations:{http_status:200,hsts:'positive',csp:'present',csp_report_only:'absent',csp_directives:[{directive:'script-src',unsafe_inline:true}],csp_report_only_directives:[],csp_effective:[{sink:'script-elem',directive:'script-src',mode:'review'},{sink:'script-attr',directive:'script-src',mode:'review'}],csp_report_only_effective:[],cookie_prefix:{state:'none_observed',violations:null},x_content_type_options:'present',referrer_policy:'absent',permissions_policy:'absent',cookies:{state:'none_observed',count:0,secure:null,httponly:null,samesite:null}}});
 const report=adaptDiscoveryLab(x); expect(report.crawl?.complete).toBe(true); expect(report.completeness).toBe('complete'); expect(renderDiscoveryReport(report,'fr')).toContain('script-src');
 p.observations.csp_effective[1].mode='uncertain'; expect(() => adaptDiscoveryLab(x)).toThrow();
 p.observations.csp_effective[1].mode='review'; p.observations.csp_directives[0].raw='SECRET'; expect(() => adaptDiscoveryLab(x)).toThrow();
});
