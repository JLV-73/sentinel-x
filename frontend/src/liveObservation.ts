import type {Locale} from './i18n';
import {renderPremiumLiveReport} from './liveReportPremium';
export type State='present'|'absent'|'indeterminate';
export type Observation={mode:'live';target:string;observed_at:string;http_status:number|null;tls:{certificate:'verified'|'indeterminate';hostname:'verified'|'indeterminate';protocol:string|null;not_before:string|null;not_after:string|null};headers:Record<'hsts'|'csp'|'x_content_type_options'|'referrer_policy'|'permissions_policy',State>;failure_code:'none'|'http_refused'|'timeout'|'tls_or_transport'|'blocked'|'incomplete'|'unknown';advanced?:unknown};
const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:Record<string,unknown>,ks:string[])=>Object.keys(v).length===ks.length&&ks.every(k=>Object.hasOwn(v,k));
const utc=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(v)&&Number(v.slice(11,13))<24&&!Number.isNaN(Date.parse(v))&&!Number.isNaN(Date.parse(v.slice(0,10)+'T00:00:00Z'))&&new Date(v.slice(0,10)+'T00:00:00Z').toISOString().slice(0,10)===v.slice(0,10);
const certDate=(v:unknown)=>{
 if(v===null)return true;
 if(typeof v!=='string'||v.length>40)return false;
 const m=/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d) (\d{4}) GMT$/.exec(v);
 if(!m)return false;
 const month=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(m[1]);
 const day=Number(m[2]),hour=Number(m[3]),minute=Number(m[4]),second=Number(m[5]),year=Number(m[6]);
 const leap=year%4===0&&(year%100!==0||year%400===0);
 const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
 // Preserve the frontend's existing 00–59 seconds contract; Python also parses leap seconds.
 return year>=1&&day>=1&&day<=days[month]&&hour<24&&minute<60&&second<60;
};
// Facts are closed, bounded projections; their contents do not attest provenance.
const directives=['default-src','script-src','script-src-elem','script-src-attr','style-src','style-src-elem','style-src-attr','img-src','connect-src','font-src','frame-src','object-src','base-uri','form-action','frame-ancestors'];
const obsKeys=['http_status','hsts','csp','csp_report_only','csp_directives','csp_report_only_directives','csp_effective','csp_report_only_effective','cookie_prefix','x_content_type_options','referrer_policy','permissions_policy','cookies'];
const inSet=(v:unknown,values:string[])=>typeof v==='string'&&values.includes(v);
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>=min&&v<=max;
function validFacts(value:unknown,status:unknown,headers:Record<string,unknown>):boolean {
 if(!obj(value)||!keys(value,['schema_version','observations','findings'])||value.schema_version!=='fortress.head-facts/1'||!obj(value.observations)||!keys(value.observations,obsKeys))return false;
 const o=value.observations;
 if(!integer(o.http_status,200,599)||o.http_status!==status||!inSet(o.hsts,['absent','positive','disabled','indeterminate']))return false;
 for(const k of ['csp','csp_report_only','x_content_type_options','referrer_policy','permissions_policy'])if(!inSet(o[k],['absent','present','indeterminate']))return false;
 for(const k of Object.keys(headers))if(headers[k]!==(o[k]==='absent'?'absent':'present'))return false;
 const expected:Record<string,string>[]=[];
 const add=(rule_id:string,qualification:string,evidence:string,recommendation:string,limit:string)=>expected.push({rule_id,qualification,priority:'unclassified',evidence,route_id:'head-route-1',recommendation,limit});
 if(o.hsts==='absent'||o.hsts==='disabled')add(`hsts.${o.hsts==='absent'?'header_absent':'disabled'}.v1`,'confirmed',o.hsts,'review_hsts_for_route','head_response_only');
 for(const [state,projection,effective,label] of [['csp','csp_directives','csp_effective','active'],['csp_report_only','csp_report_only_directives','csp_report_only_effective','report_only']]){
  const p=o[projection], e=o[effective];
  if(!Array.isArray(p)||p.length>directives.length||!Array.isArray(e)||e.length>4||(o[state]!=='present'&&(p.length>0||e.length>0)))return false;
  const byName=new Map<string,boolean>();
  for(const item of p){if(!obj(item)||!keys(item,['directive','unsafe_inline'])||!inSet(item.directive,directives)||typeof item.unsafe_inline!=='boolean'||byName.has(item.directive as string))return false;byName.set(item.directive as string,item.unsafe_inline);}
  const sinks=new Set<string>(), emitted=new Set<string>(), modes=new Map<string,string>();
  for(const item of e){
   if(!obj(item)||!keys(item,['sink','directive','mode'])||!inSet(item.sink,['script-elem','script-attr','style-elem','style-attr'])||!inSet(item.mode,['review','uncertain'])||sinks.has(item.sink as string))return false;
   const [kind,suffix]=(item.sink as string).split('-');
   const applicable=[`${kind}-src-${suffix}`,`${kind}-src`,'default-src'].find(n=>byName.has(n));
   if(!applicable||item.directive!==applicable||!byName.get(applicable))return false;
   if(modes.has(applicable)&&modes.get(applicable)!==item.mode)return false;
   modes.set(applicable,item.mode as string);
   sinks.add(item.sink as string);
   const key=applicable+':'+item.mode;
   if(!emitted.has(key)){emitted.add(key);add(`csp.${label}_inline.v1`,'investigate',applicable,item.mode==='review'?'review_inline_in_context':'review_policy_semantics','effect_not_determined');}
  }
  for(const kind of ['script','style'])for(const suffix of ['elem','attr']){const applicable=[`${kind}-src-${suffix}`,`${kind}-src`,'default-src'].find(n=>byName.has(n));if(applicable&&byName.get(applicable)&&!sinks.has(`${kind}-${suffix}`))return false;}
 }
 const c=o.cookies,p=o.cookie_prefix;
 if(!obj(c)||!keys(c,['state','count','secure','httponly','samesite'])||!integer(c.count,0,16384)||!obj(p)||!keys(p,['state','violations'])||p.state!==c.state)return false;
 const attrs=['secure','httponly','samesite'];
 if(c.state==='none_observed'){if(c.count!==0||attrs.some(k=>c[k]!==null)||p.violations!==null)return false;}
 else if(c.state==='indeterminate'){if(c.count<1||attrs.some(k=>c[k]!==null)||p.violations!==null)return false;add('cookie.syntax_indeterminate.v1','investigate','syntax_indeterminate','review_cookie_syntax_in_context','acceptance_and_usage_unknown');}
 else if(c.state==='observed'){
  if(c.count<1||attrs.some(k=>!integer(c[k],0,c.count as number))||!integer(p.violations,0,c.count))return false;
  for(const k of ['secure','httponly'])if((c[k] as number)<c.count)add(`cookie.missing_${k}.v1`,'investigate','attribute_missing_on_some','review_cookie_attributes_in_context','acceptance_and_usage_unknown');
  if(p.violations>0)add('cookie.prefix_requirements.v1','investigate','prefix_requirements_not_met','review_cookie_prefix_in_context','acceptance_and_usage_unknown');
 }else return false;
 if(!Array.isArray(value.findings)||value.findings.length!==expected.length)return false;
 return value.findings.every((item,i)=>obj(item)&&keys(item,Object.keys(expected[i]))&&Object.entries(expected[i]).every(([k,v])=>item[k]===v));
}
export function validInput(value:string):boolean {try{const u=new URL(value);return value===value.trim()&&u.protocol==='https:'&&!!u.hostname&&!u.username&&!u.password&&!u.hash;}catch{return false;}}
export function parseObservation(raw:unknown,input:string):Observation {
 const fail=():never=>{throw new Error('invalid');};
 if(!validInput(input)||!obj(raw)||!keys(raw,Object.hasOwn(raw,'advanced')?['mode','target','observed_at','http_status','tls','headers','failure_code','advanced']:['mode','target','observed_at','http_status','tls','headers','failure_code'])||raw.mode!=='live'||typeof raw.target!=='string')return fail();
 let target:URL;try{target=new URL(raw.target);}catch{return fail();}
 if(target.protocol!=='https:'||target.username||target.password||target.search||target.hash||target.pathname!=='/'||target.origin!==new URL(input).origin||!/^https:\/\/(?:[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?\/$/.test(raw.target))return fail();
 if(!utc(raw.observed_at)||!(raw.http_status===null||(Number.isInteger(raw.http_status)&&Number(raw.http_status)>=200&&Number(raw.http_status)<=599)))return fail();
 if(!obj(raw.tls)||!keys(raw.tls,['certificate','hostname','protocol','not_before','not_after']))return fail();
 if(typeof raw.tls.certificate!=='string'||!['verified','indeterminate'].includes(raw.tls.certificate)||typeof raw.tls.hostname!=='string'||!['verified','indeterminate'].includes(raw.tls.hostname)||!(raw.tls.protocol===null||(typeof raw.tls.protocol==='string'&&['TLSv1','TLSv1.1','TLSv1.2','TLSv1.3'].includes(raw.tls.protocol)))||!certDate(raw.tls.not_before)||!certDate(raw.tls.not_after))return fail();
 const hs=['hsts','csp','x_content_type_options','referrer_policy','permissions_policy'];
 if(!obj(raw.headers)||!keys(raw.headers,hs)||hs.some(k=>typeof (raw.headers as Record<string,unknown>)[k]!=='string'||!['present','absent','indeterminate'].includes((raw.headers as Record<string,string>)[k])))return fail();
 if(typeof raw.failure_code!=='string'||!['none','http_refused','tls_or_transport','timeout','blocked','incomplete','unknown'].includes(raw.failure_code))return fail();
 if(raw.tls.certificate!==raw.tls.hostname)return fail();
 const verified=raw.tls.certificate==='verified';
 if(verified ? [raw.tls.protocol,raw.tls.not_before,raw.tls.not_after].some(v=>v===null) : [raw.tls.protocol,raw.tls.not_before,raw.tls.not_after].some(v=>v!==null))return fail();
 if(raw.http_status===null){if(raw.failure_code==='none'||raw.failure_code==='http_refused'||hs.some(k=>(raw.headers as Record<string,unknown>)[k]!=='indeterminate'))return fail();}
 else if(!verified||hs.some(k=>(raw.headers as Record<string,unknown>)[k]==='indeterminate')||raw.failure_code!==(Number(raw.http_status)>=400?'http_refused':'none'))return fail();
 if(Object.hasOwn(raw,'advanced')&&(raw.http_status===null?raw.advanced!==null:!validFacts(raw.advanced,raw.http_status,raw.headers)))return fail();
 return raw as Observation;
}
export function renderLiveReport(o:Observation,locale:Locale):string {
 let safe:Observation|null=null;
 try { safe=parseObservation(o,typeof o?.target==='string'?o.target:''); } catch { /* malformed data is never promoted into evidence */ }
 return renderPremiumLiveReport(safe,locale);
}
