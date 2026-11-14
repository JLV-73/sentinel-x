import {validatePartialHeaders, type PartialHeaders} from './discoveryPartialHeaders';
import {adaptDiscoveryLab} from './discoveryLabAdapter';
import {isSanitizedPath} from './discoverySafePath';
import type {PassiveSecurity} from './discoveryReport';
// Fail closed on unrecognised fields: raw response content must never reach a report.
export type DiscoveryApiPage={id:string;route:string;depth:number;status:number|null;state:string;observed_at:string|null;findings:any[];observations:any;partial_headers?:PartialHeaders;tls?:{version:'TLSv1.2'|'TLSv1.3'|'unknown';certificate_verified:true;hostname_verified:true;not_after:string|null}};
export type DiscoveryDiagnostic={phase:'dns'|'scope'|'connect'|'tls'|'timeout'|'http'|'parse'|'budget'|'unknown'|'none';requests_sent:number|null;responses_received:number|null};
export type DiscoveryApiResponse={schema:'fortress.discovery/1';provenance:'lab'|'live';complete:boolean;reason:string;requests:number;bytes:number;pages:DiscoveryApiPage[];relations:{from:string;to:string;kind:'link'|'redirect'}[];resources:{page:string;kind:'script'|'stylesheet'|'form'|'api';count:number}[];limits:string[];graph_omitted_relations?:number;diagnostic?:DiscoveryDiagnostic;exclusion_reasons?:Record<'external'|'query_fragment'|'sensitive'|'non_html_resource'|'invalid'|'out_of_scope'|'depth'|'unknown',number>;private_paths?:{id:string;path:string}[]};
const fail=():never=>{throw new TypeError('Unsupported discovery response');};
// The existing adapter checks the entire passive observation and rule tuple.
// This temporary single-page envelope is never exported; identifiers are aliases.
export function securityProjection(p:DiscoveryApiPage,index:number):PassiveSecurity{
 if((p.status!==200&&p.status!==204)||p.observed_at===null)fail();
 const limits=['caller_declared_provenance','effective_route_declared_by_caller','response_headers_only','method_unknown','positional_route_labels','no_vulnerability_or_compliance_conclusion'];
 const graphRoute='route-'+'a'.repeat(64);
 const findings=p.findings.map((f:any)=>{if(!f||f.route!==p.route)fail();return {...f,route:'page-1'};});
 const result=adaptDiscoveryLab({pages:1,requests:1,bytes:0,complete:true,reason:'none',graph:{pages:[{route:graphRoute,depth:0,status:p.status}],relations:[],resources:[]},intelligence:{schema_version:'fortress.discovery-intelligence/1',limits,pages:[{route:'page-1',observed_at:p.observed_at,status:p.status,state:'complete',method:'unknown',provenance:{kind:'caller_declared',attestation:'none'},confidence:'caller_declared',observations:p.observations,findings,limits,graph_route:graphRoute}]}});
 return {...result.security![0],page:index};
}
function obj(x:unknown,keys:string[]):asserts x is Record<string,any>{if(!x||typeof x!=='object'||Array.isArray(x)||Object.getPrototypeOf(x)!==Object.prototype||Reflect.ownKeys(x).length!==keys.length||keys.some(k=>!Object.hasOwn(x,k)))fail();}
function integer(x:unknown,max:number):asserts x is number{if(!Number.isSafeInteger(x)||(x as number)<0||(x as number)>max)fail();}
function list(x:unknown,max:number):asserts x is any[]{if(!Array.isArray(x)||x.length>max)fail();}
function text(x:unknown,max:number):asserts x is string{if(typeof x!=='string'||x.length<1||x.length>max||/[\x00-\x1f\x7f]/.test(x))fail();}
export function parseDiscoveryResponse(x:unknown,expected:'lab'|'live'):DiscoveryApiResponse{
 obj(x,['schema','provenance','complete','reason','requests','bytes','pages','relations','resources','limits',...(['diagnostic','exclusion_reasons','private_paths','graph_omitted_relations'].filter(k=>x&&typeof x==='object'&&Object.hasOwn(x,k)))]);
 if(x.schema!=='fortress.discovery/1'||x.provenance!==expected||typeof x.complete!=='boolean')fail();
 if(!['none','unknown','scope_blocked','request_limit','duration_limit','byte_limit','redirect_blocked','redirect_loop','page_limit','depth_limit','http_refused','incomplete','transport_error'].includes(x.reason))fail();
 if(x.complete!==(x.reason==='none'))fail();integer(x.requests,30);integer(x.bytes,11000000);
 if(Object.hasOwn(x,'diagnostic')){const d=x.diagnostic;obj(d,['phase','requests_sent','responses_received']);if(!['dns','scope','connect','tls','timeout','http','parse','budget','unknown','none'].includes(d.phase))fail();for(const v of [d.requests_sent,d.responses_received])if(v!==null)integer(v,30);if(d.requests_sent!==null&&d.requests_sent>x.requests||d.responses_received!==null&&d.responses_received>x.requests||d.requests_sent!==null&&d.responses_received!==null&&d.responses_received>d.requests_sent)fail();}
 list(x.pages,100);list(x.relations,2000);list(x.resources,2000);list(x.limits,50);
 if(Object.hasOwn(x,'graph_omitted_relations')){integer(x.graph_omitted_relations,30000);if(x.graph_omitted_relations===0||x.graph_omitted_relations+x.relations.length>30000)fail();}
 if(Object.hasOwn(x,'diagnostic')){
  const d=x.diagnostic;
  const phases:Record<string,string>={none:'none',scope_blocked:'scope',redirect_blocked:'scope',redirect_loop:'scope',http_refused:'http',request_limit:'budget',page_limit:'budget',byte_limit:'budget',depth_limit:'budget',unknown:'unknown'};
  if((d.phase==='none')!==x.complete||Object.hasOwn(phases,x.reason)&&d.phase!==phases[x.reason]||x.reason==='duration_limit'&&!['budget','timeout'].includes(d.phase))fail();
  if(d.responses_received!==null&&d.responses_received<x.pages.length||x.complete&&(d.requests_sent!==null&&d.requests_sent!==x.requests||d.responses_received!==null&&d.responses_received!==x.requests))fail();
 }
 if(expected==='live'){
  if(x.bytes>10485760||x.pages.length>x.requests||x.relations.length>1000||x.resources.length>100||x.limits.length!==5||!/^excluded_links:[0-9]{1,5}$/.test(x.limits[0])||x.limits.slice(1).join('|')!=='no_external_requests|no_authentication|headers_only_analysis|not_a_vulnerability_or_compliance_conclusion')fail();
  x.pages.forEach((p:any,i:number)=>{if(p.id!==`page-${i+1}`||(p.route!==p.id&&!isSanitizedPath(p.route))||p.depth>2||!Number.isInteger(p.status)||p.status<200||typeof p.observed_at!=='string')fail();});
  x.resources.forEach((r:any)=>{if(!Number.isInteger(r.count)||r.count<1||r.count>1000)fail();});
 }
 const ids=new Set<string>();
 for(const p of x.pages){obj(p,['id','route','depth','status','state','observed_at','findings','observations',...(['partial_headers','tls'].filter(k=>p&&typeof p==='object'&&Object.hasOwn(p,k)))]);if(Object.hasOwn(p,'tls')){const t=p.tls;obj(t,['version','certificate_verified','hostname_verified','not_after']);if(!['TLSv1.2','TLSv1.3','unknown'].includes(t.version)||t.certificate_verified!==true||t.hostname_verified!==true)fail();if(t.not_after!==null){if(typeof t.not_after!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(t.not_after)||!Number.isFinite(Date.parse(t.not_after))||new Date(t.not_after).toISOString()!==t.not_after.replace('Z','.000Z')||t.not_after.startsWith('0000'))fail();}}if(Object.hasOwn(p,'partial_headers')){if(p.state!=='incomplete'||p.status===null)fail();validatePartialHeaders(p.partial_headers);}text(p.id,128);text(p.route,128);if(!/^page-[1-9][0-9]{0,2}(?![\s\S])$/.test(p.id)||(p.route!==p.id&&!isSanitizedPath(p.route))||ids.has(p.id))fail();ids.add(p.id);integer(p.depth,100);if(p.status!==null){integer(p.status,599);if(p.status<100)fail();}if(!['complete','access_denied','redirected','incomplete','http_error'].includes(p.state))fail();if(p.state==='access_denied'&&p.status!==403||p.state==='complete'&&(p.status===null||p.status<200||p.status>=300)||p.state==='incomplete'&&p.status!==null&&(p.status<200||x.complete||!['unknown','incomplete','byte_limit','duration_limit','transport_error'].includes(x.reason))||p.state==='redirected'&&(p.status===null||p.status<300||p.status>=400||p.status===304)||p.state==='http_error'&&(p.status===null||p.status<400||p.status===403))fail();if(p.observed_at!==null&&(typeof p.observed_at!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(p.observed_at)||!Number.isFinite(Date.parse(p.observed_at))))fail();list(p.findings,100);if(p.state==='complete') securityProjection(p as DiscoveryApiPage,0); else if(p.findings.length||p.observations!==null)fail();}
 const destinations=new Set<string>();
 for(const r of x.relations){obj(r,['from','to','kind']);text(r.to,128);if(!ids.has(r.from)||!/^page-[1-9][0-9]{0,2}(?![\s\S])/.test(r.to)||!['link','redirect'].includes(r.kind))fail();if(!ids.has(r.to))destinations.add(r.to);}
 // Live worker aliases are three-digit page-N values; keep lab's older cap.
 if(ids.size+destinations.size>(expected==='live'?999:500)||x.complete&&destinations.size>0)fail();
 if(Object.hasOwn(x,'exclusion_reasons')){const keys=['external','query_fragment','sensitive','non_html_resource','invalid','out_of_scope','depth','unknown'];obj(x.exclusion_reasons,keys);let total=0;for(const key of keys){integer(x.exclusion_reasons[key],30000);total+=x.exclusion_reasons[key];}const limit=x.limits.find((v:any)=>typeof v==='string'&&/^excluded_links:[0-9]{1,5}$/.test(v));if(!limit||total>30000||total>Number(limit.split(':')[1]))fail();}
 if(Object.hasOwn(x,'private_paths')){list(x.private_paths,999);if(expected!=='live'||x.private_paths.length!==ids.size+destinations.size)fail();const seen=new Set<string>();const allowed=new Set(['about','contact','help','team','pricing','products','services','blog','news','faq','legal','privacy','terms','[masqué]']);for(const entry of x.private_paths){obj(entry,['id','path']);if(typeof entry.id!=='string'||(!ids.has(entry.id)&&!destinations.has(entry.id))||seen.has(entry.id))fail();seen.add(entry.id);if(typeof entry.path!=='string'||!entry.path.startsWith('/')||entry.path!=='/'&&(entry.path.slice(1).split('/').length>8||entry.path.slice(1).split('/').some((s:string)=>!allowed.has(s))))fail();}}
 for(const r of x.resources){obj(r,['page','kind','count']);if(!ids.has(r.page)||!['script','stylesheet','form','api'].includes(r.kind))fail();integer(r.count,100000);}
 for(const l of x.limits)if(typeof l!=='string'||(!['lab_only','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion'].includes(l)&&!/^excluded_links:[0-9]{1,6}$/.test(l)))fail();
 return x as DiscoveryApiResponse;
}
