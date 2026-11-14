import {describe,it,expect} from 'vitest';
import {parseDiscoveryResponse} from './discoveryApi';

const response=()=>({schema:'fortress.discovery/1',provenance:'lab',complete:false,reason:'http_refused',requests:1,bytes:0,pages:[{id:'page-1',route:'page-1',depth:0,status:403,state:'access_denied',observed_at:null,findings:[],observations:null}],relations:[],resources:[],limits:[]});
describe('discovery API boundary',()=>{
 it('accepts a 403 observation without turning it into a finding',()=>{const r=parseDiscoveryResponse(response(),'lab');expect(r.pages[0].status).toBe(403);expect(r.pages[0].findings).toEqual([]);});
 it('rejects provenance mismatch and unrecognized raw values',()=>{expect(()=>parseDiscoveryResponse(response(),'live')).toThrow();expect(()=>parseDiscoveryResponse({...response(),raw:'SECRET<script>'},'lab')).toThrow();const x=response();x.pages[0].route='<script>SECRET</script>';expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();});
 it('accepts unresolved destinations without changing the API facts',()=>{const x:any=response();x.reason='depth_limit';x.relations=[{from:'page-1',to:'page-2',kind:'link'},{from:'page-1',to:'page-2',kind:'redirect'}];const before=JSON.stringify(x);expect(parseDiscoveryResponse(x,'lab')).toEqual(x);expect(JSON.stringify(x)).toBe(before);});
 it('fails closed on unsafe or contradictory relation endpoints',()=>{for(const to of ['page-0','page-01','page-1000','page-2\n','page-2\u2028','<script>SECRET</script>','https://example.org']){const x:any=response();x.relations=[{from:'page-1',to,kind:'link'}];expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();}const x:any=response();x.relations=[{from:'page-2',to:'page-1',kind:'link'}];expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();x.relations=[{from:'page-1',to:'page-2',kind:'link',raw:'SECRET'}];expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();x.relations=[{from:'page-1',to:'page-2',kind:'link'}];x.resources=[{page:'page-2',kind:'script',count:1}];expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();x.resources=[];x.complete=true;x.reason='none';expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();});
 it('bounds the combined observed and unresolved graph',()=>{const x:any=response();x.relations=Array.from({length:500},(_,i)=>({from:'page-1',to:`page-${i+2}`,kind:'link'}));expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();x.relations.pop();expect(()=>parseDiscoveryResponse(x,'lab')).not.toThrow();});
 it('accepts structured passive observations but rejects raw injected fields',()=>{const x:any=response();x.complete=true;x.reason='none';x.relations=[{from:'page-1',to:'page-1',kind:'link'}];Object.assign(x.pages[0],{status:200,state:'complete',observed_at:'2026-11-12T12:00:00Z',observations:{http_status:200,hsts:'positive',csp:'absent',csp_report_only:'absent',csp_directives:[],csp_report_only_directives:[],csp_effective:[],csp_report_only_effective:[],cookie_prefix:{state:'none_observed',violations:null},x_content_type_options:'present',referrer_policy:'absent',permissions_policy:'absent',cookies:{state:'none_observed',count:0,secure:null,httponly:null,samesite:null}}});expect(()=>parseDiscoveryResponse(x,'lab')).not.toThrow();x.pages[0].observations.raw='SECRET<script>';expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();});
});

it('rejects diagnostic phase and counter contradictions with the backend contract',()=>{
 const blocked={...response(),provenance:'live',reason:'scope_blocked',requests:0,pages:[],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion']};
 expect(()=>parseDiscoveryResponse({...blocked,diagnostic:{phase:'none',requests_sent:0,responses_received:0}},'live')).toThrow();
 for(const [reason,phase] of [['scope_blocked','scope'],['redirect_blocked','scope'],['redirect_loop','scope'],['http_refused','http'],['request_limit','budget'],['page_limit','budget'],['byte_limit','budget'],['depth_limit','budget'],['unknown','unknown']]){
  const x={...response(),reason,diagnostic:{phase,requests_sent:1,responses_received:1}};
  expect(()=>parseDiscoveryResponse(x,'lab')).not.toThrow();
  expect(()=>parseDiscoveryResponse({...x,diagnostic:{...x.diagnostic,phase:phase==='http'?'scope':'http'}},'lab')).toThrow();
 }
 for(const phase of ['budget','timeout']) expect(()=>parseDiscoveryResponse({...response(),reason:'duration_limit',diagnostic:{phase,requests_sent:1,responses_received:1}},'lab')).not.toThrow();
 expect(()=>parseDiscoveryResponse({...response(),reason:'duration_limit',diagnostic:{phase:'http',requests_sent:1,responses_received:1}},'lab')).toThrow();
 expect(()=>parseDiscoveryResponse({...response(),diagnostic:{phase:'http',requests_sent:1,responses_received:0}},'lab')).toThrow();
 const complete={...response(),complete:true,reason:'none',requests:2,diagnostic:{phase:'none',requests_sent:1,responses_received:1}};
 expect(()=>parseDiscoveryResponse(complete,'lab')).toThrow();
});

it('validates the optional diagnostic without altering historical or new responses',()=>{
 const historical=response(); expect(parseDiscoveryResponse(historical,'lab')).toEqual(historical);
 for(const phase of ['dns','scope','connect','tls','timeout','http','parse','budget','unknown']){
  const x={...response(),reason:'transport_error',diagnostic:{phase,requests_sent:1,responses_received:1}};expect(parseDiscoveryResponse(x,'lab')).toEqual(x);
 }
 const completed={...response(),complete:true,reason:'none',diagnostic:{phase:'none',requests_sent:1,responses_received:1}};expect(parseDiscoveryResponse(completed,'lab')).toEqual(completed);
 for(const diagnostic of [null,{}, {phase:'TLS',requests_sent:0,responses_received:0}, {phase:'tls',requests_sent:-1,responses_received:0}, {phase:'tls',requests_sent:1.5,responses_received:null}, {phase:'tls',requests_sent:2,responses_received:0}, {phase:'tls',requests_sent:0,responses_received:1}, {phase:'tls',requests_sent:null,responses_received:2}, {phase:'tls',requests_sent:0,responses_received:0,extra:'x'}, {phase:'tls',requests_sent:'1',responses_received:0}]) expect(()=>parseDiscoveryResponse({...response(),reason:'transport_error',diagnostic},'lab')).toThrow();
 expect(()=>parseDiscoveryResponse({...response(),reason:'unknown',diagnostic:{phase:'unknown',requests_sent:null,responses_received:null}},'lab')).not.toThrow();
});


it('validates optional attestations, exclusions and private aliases',()=>{
 const x:any=response();x.provenance='live';x.pages[0].observed_at='2026-11-12T12:00:00Z';x.limits=['excluded_links:2','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion'];x.exclusion_reasons={external:1,query_fragment:0,sensitive:1,non_html_resource:0,invalid:0,out_of_scope:0,depth:0,unknown:0};x.pages[0].tls={version:'TLSv1.3',certificate_verified:true,hostname_verified:true,not_after:'2028-02-29T12:00:00Z'};x.relations=[{from:'page-1',to:'page-2',kind:'link'}];x.private_paths=[{id:'page-1',path:'/'},{id:'page-2',path:'/about/[masqué]'}];
 expect(parseDiscoveryResponse(x,'live')).toEqual(x);
 for(const mutate of [(v:any)=>v.pages[0].tls.not_after='2027-02-29T00:00:00Z',(v:any)=>v.pages[0].tls.hostname_verified=false,(v:any)=>v.exclusion_reasons.external=2,(v:any)=>v.private_paths.push(v.private_paths[0]),(v:any)=>v.private_paths[0].path='/about/FAKESECRET',(v:any)=>v.private_paths[0].id='page-3']){const v=structuredClone(x);mutate(v);expect(()=>parseDiscoveryResponse(v,'live')).toThrow();}
});
