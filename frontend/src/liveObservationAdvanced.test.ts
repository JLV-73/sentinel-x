import {describe,it,expect} from 'vitest';
import {parseObservation,renderLiveReport} from './liveObservation';
const input='https://example.org/private?secret=1';
const legacy=()=>({mode:'live',target:'https://example.org/',observed_at:'2026-01-01T00:00:00Z',http_status:200,tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3',not_before:'Jan  1 00:00:00 2026 GMT',not_after:'Jan  1 00:00:00 2027 GMT'},headers:{hsts:'absent',csp:'absent',x_content_type_options:'absent',referrer_policy:'absent',permissions_policy:'absent'},failure_code:'none'});
const facts=()=>({schema_version:'fortress.head-facts/1',observations:{http_status:200,hsts:'absent',csp:'absent',csp_report_only:'absent',csp_directives:[],csp_report_only_directives:[],csp_effective:[],csp_report_only_effective:[],cookie_prefix:{state:'none_observed',violations:null},x_content_type_options:'absent',referrer_policy:'absent',permissions_policy:'absent',cookies:{state:'none_observed',count:0,secure:null,httponly:null,samesite:null}},findings:[{rule_id:'hsts.header_absent.v1',qualification:'confirmed',priority:'unclassified',evidence:'absent',route_id:'head-route-1',recommendation:'review_hsts_for_route',limit:'head_response_only'}]});
describe('Cycle B live facts',()=>{
 it('renders advanced facts rather than the historical summary',()=>{const o=parseObservation({...legacy(),advanced:facts()},input);for(const locale of ['fr','en'] as const){const report=renderLiveReport(o,locale);expect(report).toContain('hsts.header_absent.v1');expect(report).not.toContain(locale==='fr'?'Les détails avancés ne sont pas affichés dans ce résumé.':'Advanced details are not shown in this summary.');}});
 it('accepts legacy and a bounded advanced result without changing either',()=>{const old=legacy(),current={...legacy(),advanced:facts()};expect(parseObservation(old,input)).toEqual(old);expect(parseObservation(current,input)).toEqual(current);});
 it('accepts null facts only for an incomplete attempt',()=>{const g=legacy();const blocked={...g,http_status:null,headers:Object.fromEntries(Object.keys(g.headers).map(k=>[k,'indeterminate'])),failure_code:'blocked',tls:{certificate:'indeterminate',hostname:'indeterminate',protocol:null,not_before:null,not_after:null},advanced:null};expect(parseObservation(blocked,input)).toEqual(blocked);expect(()=>parseObservation({...g,advanced:null},input)).toThrow();expect(()=>parseObservation({...blocked,advanced:facts()},input)).toThrow();});
 it('rejects unknown, secret-bearing, synthetic or malformed fields at every level',()=>{
  const f=facts();const bad=[{...f,provenance:{kind:'fixture'}},{...f,schema_version:'fortress.report/1'},{...f,observations:{...f.observations,raw:'secret'}},{...f,observations:{...f.observations,cookies:{...f.observations.cookies,name:'secret'}}},{...f,observations:{...f.observations,cookie_prefix:{...f.observations.cookie_prefix,value:'secret'}}},{...f,findings:[{...f.findings[0],raw:'secret'}]},{...f,findings:[{...f.findings[0],route_id:'fixture-route-1'}]},{...f,findings:[]},{...f,findings:[{...f.findings[0],qualification:'compliant'}]}];
  for(const advanced of bad)expect(()=>parseObservation({...legacy(),advanced},input)).toThrow();
  expect(()=>parseObservation({...legacy(),mode:'fixture',advanced:f},input)).toThrow();
  expect(()=>parseObservation({...legacy(),synthetic:true,advanced:f},input)).toThrow();
 });
 it('rejects inconsistent status, header, cookies and prefix counts',()=>{
  const f=facts(),o=f.observations;
  const invalid=[{...o,http_status:201},{...o,hsts:'positive'},{...o,cookies:{...o.cookies,count:1}},{...o,cookies:{state:'observed',count:1,secure:2,httponly:1,samesite:1},cookie_prefix:{state:'observed',violations:0}},{...o,cookies:{state:'indeterminate',count:1,secure:null,httponly:null,samesite:null}},{...o,cookies:{state:'observed',count:16385,secure:1,httponly:1,samesite:1},cookie_prefix:{state:'observed',violations:0}},{...o,cookie_prefix:{state:'none_observed',violations:0}}];
  for(const observations of invalid)expect(()=>parseObservation({...legacy(),advanced:{...f,observations}},input)).toThrow();
 });
 it('validates CSP fallback and deduplicated findings',()=>{
  const f=facts();const observations={...f.observations,csp:'present',csp_directives:[{directive:'script-src',unsafe_inline:true}],csp_effective:[{sink:'script-elem',directive:'script-src',mode:'review'},{sink:'script-attr',directive:'script-src',mode:'review'}]};
  const finding={rule_id:'csp.active_inline.v1',qualification:'investigate',priority:'unclassified',evidence:'script-src',route_id:'head-route-1',recommendation:'review_inline_in_context',limit:'effect_not_determined'};
  const response={...legacy(),headers:{...legacy().headers,csp:'present'},advanced:{...f,observations,findings:[...f.findings,finding]}};
  expect(parseObservation(response,input)).toEqual(response);
  for(const change of [{...observations,csp_effective:observations.csp_effective.slice(0,1)},{...observations,csp_directives:[...observations.csp_directives,...observations.csp_directives]},{...observations,csp_effective:[{...observations.csp_effective[0],directive:'default-src'},observations.csp_effective[1]]},{...observations,csp_directives:[{directive:'script-src',unsafe_inline:true,raw:'secret'}]}])expect(()=>parseObservation({...response,advanced:{...response.advanced,observations:change}},input)).toThrow();
 });
 it('rejects conflicting modes for the same CSP directive in each policy',()=>{
  for(const reportOnly of [false,true])for(const reverse of [false,true]){
   const f=facts(),label=reportOnly?'report_only':'active';
   const modes=reverse?['uncertain','review']:['review','uncertain'];
   const effective=['script-elem','script-attr'].map((sink,i)=>({sink,directive:'script-src',mode:modes[i]}));
   const findings=modes.map(mode=>({rule_id:`csp.${label}_inline.v1`,qualification:'investigate',priority:'unclassified',evidence:'script-src',route_id:'head-route-1',recommendation:mode==='review'?'review_inline_in_context':'review_policy_semantics',limit:'effect_not_determined'}));
   const observations={...f.observations,...(reportOnly?{csp_report_only:'present',csp_report_only_directives:[{directive:'script-src',unsafe_inline:true}],csp_report_only_effective:effective}:{csp:'present',csp_directives:[{directive:'script-src',unsafe_inline:true}],csp_effective:effective})};
   const response={...legacy(),headers:{...legacy().headers,csp:reportOnly?'absent':'present'},advanced:{...f,observations,findings:[...f.findings,...findings]}};
   expect(()=>parseObservation(response,input)).toThrow();
  }
 });
 it('accepts different modes on different directives and on separate policies',()=>{
  const f=facts();
  const observations={...f.observations,csp:'present',csp_report_only:'present',csp_directives:[{directive:'script-src',unsafe_inline:true},{directive:'style-src',unsafe_inline:true}],csp_report_only_directives:[{directive:'script-src',unsafe_inline:true}],csp_effective:[{sink:'script-elem',directive:'script-src',mode:'review'},{sink:'script-attr',directive:'script-src',mode:'review'},{sink:'style-elem',directive:'style-src',mode:'uncertain'},{sink:'style-attr',directive:'style-src',mode:'uncertain'}],csp_report_only_effective:[{sink:'script-elem',directive:'script-src',mode:'uncertain'},{sink:'script-attr',directive:'script-src',mode:'uncertain'}]};
  const finding=(label:string,evidence:string,mode:string)=>({rule_id:`csp.${label}_inline.v1`,qualification:'investigate',priority:'unclassified',evidence,route_id:'head-route-1',recommendation:mode==='review'?'review_inline_in_context':'review_policy_semantics',limit:'effect_not_determined'});
  const response={...legacy(),headers:{...legacy().headers,csp:'present'},advanced:{...f,observations,findings:[...f.findings,finding('active','script-src','review'),finding('active','style-src','uncertain'),finding('report_only','script-src','uncertain')]}};
  expect(parseObservation(response,input)).toEqual(response);
 });
 it('accepts counted cookies only with exact derived findings',()=>{
  const f=facts();const observations={...f.observations,cookies:{state:'observed',count:2,secure:1,httponly:2,samesite:0},cookie_prefix:{state:'observed',violations:1}};
  const item=(rule_id:string,evidence:string,recommendation:string)=>({rule_id,qualification:'investigate',priority:'unclassified',evidence,route_id:'head-route-1',recommendation,limit:'acceptance_and_usage_unknown'});
  const findings=[...f.findings,item('cookie.missing_secure.v1','attribute_missing_on_some','review_cookie_attributes_in_context'),item('cookie.prefix_requirements.v1','prefix_requirements_not_met','review_cookie_prefix_in_context')];
  const response={...legacy(),advanced:{...f,observations,findings}};expect(parseObservation(response,input)).toEqual(response);expect(()=>parseObservation({...response,advanced:{...response.advanced,findings:findings.slice(0,2)}},input)).toThrow();
 });
});
