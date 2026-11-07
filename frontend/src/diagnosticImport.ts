// Local, data-only schema. This module never resolves or contacts the target.
export const MAX_IMPORT_BYTES=65536;
const states=['present','absent','unknown'] as const;
type State=typeof states[number];
export interface DiagnosticImport {
 mode:'import'; version:1; provenance:'original_sanitized_observations'|'report_transcription'; target:string; observed_at:string; method:'GET'; scope:'root_only'; http_status:number;
 tls:{protocol:'TLSv1.2'|'TLSv1.3'|'unknown'; certificate:'verified'|'unknown'; hostname:'verified'|'unknown'; not_before:string|null; not_after:string|null; revocation:'not_checked'|'unknown'};
 headers:{hsts:{state:State;max_age_seconds:number|null;include_subdomains:boolean|null};csp:{state:State;unsafe_inline:boolean|null;wildcard:boolean|null;location:'unknown'};csp_report_only?:{state:State;unsafe_inline:boolean|null;wildcard:boolean|null;location:'unknown'};referrer_policy:'strict-origin-when-cross-origin'|'absent'|'unknown';x_content_type_options:'nosniff'|'absent'|'unknown';permissions_policy:State};
 cookies:{count:number;secure:number;httponly:number;samesite_absent:number};
}
const fail=():never=>{throw new Error('Invalid diagnostic import');};
const record=(x:unknown,keys:string[]):Record<string,unknown>=>{if(!x||typeof x!=='object'||Array.isArray(x)||Object.getPrototypeOf(x)!==Object.prototype)return fail();const o=x as Record<string,unknown>;if(Object.keys(o).length!==keys.length||keys.some(k=>!Object.hasOwn(o,k)))return fail();return o;};
const one=(v:unknown,allowed:readonly unknown[])=>{if(!allowed.includes(v))fail();};
const integer=(v:unknown,min:number,max:number)=>{if(typeof v!=='number'||!Number.isSafeInteger(v)||v<min||v>max)fail();};
const timestamp=(v:unknown):number=>{if(typeof v!=='string')return fail();const m=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$/.exec(v);if(!m)return fail();const [,ys,ms,ds,hs,mis,ss,zone]=m;const [y,mo,d,h,mi,s]=[ys,ms,ds,hs,mis,ss].map(Number);if(y<1970||mo<1||mo>12||d<1||d>new Date(Date.UTC(y,mo,0)).getUTCDate()||h>23||mi>59||s>59)return fail();if(zone!=='Z'&&(Number(zone.slice(1,3))>14||Number(zone.slice(4,6))>59||(zone.slice(1,3)==='14'&&zone.slice(4,6)!=='00')))return fail();const n=Date.parse(v);if(!Number.isFinite(n))return fail();return n;};
// Scan the already-valid JSON grammar to reject repeated object member names,
// including escaped spellings such as "target" and "\u0074arget".
function rejectDuplicates(text:string){let i=0;const ws=()=>{while(/\s/.test(text[i]||'')&&i<text.length)i++;};const str=()=>{const start=i++;while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"')return JSON.parse(text.slice(start,i)) as string;}return fail();};const value=():void=>{ws();const c=text[i];if(c==='"'){str();return;}if(c==='{'){i++;ws();const keys=new Set<string>();if(text[i]==='}'){i++;return;}for(;;){ws();const k=str();if(keys.has(k))fail();keys.add(k);ws();i++;value();ws();if(text[i++]==='}')return;}}if(c==='['){i++;ws();if(text[i]===']'){i++;return;}for(;;){value();ws();if(text[i++]===']')return;}}while(i<text.length&&!/[\s,}\]]/.test(text[i]))i++;};value();}
export function validateDiagnostic(input:unknown):DiagnosticImport {
 const x=record(input,['mode','version','provenance','target','observed_at','method','scope','http_status','tls','headers','cookies']);one(x.mode,['import']);one(x.version,[1]);one(x.provenance,['original_sanitized_observations','report_transcription']);one(x.method,['GET']);one(x.scope,['root_only']);
 if(typeof x.target!=='string'||x.target.length>260||!/^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\/$/.test(x.target)||x.target.slice(8,-1).length>253)fail();
 const observed=timestamp(x.observed_at);integer(x.http_status,200,599);
 const t=record(x.tls,['protocol','certificate','hostname','not_before','not_after','revocation']);one(t.protocol,['TLSv1.2','TLSv1.3','unknown']);one(t.certificate,['verified','unknown']);one(t.hostname,['verified','unknown']);one(t.revocation,['not_checked','unknown']);if(t.not_before!==null&&t.not_after!==null){if(timestamp(t.not_before)>observed||timestamp(t.not_after)<observed||timestamp(t.not_before)>=timestamp(t.not_after))fail();}else if(t.not_before!==null||t.not_after!==null)fail();if((t.certificate==='verified'||t.hostname==='verified')&&(t.protocol==='unknown'||t.certificate!=='verified'||t.hostname!=='verified'))fail();
 const headerKeys=['hsts','csp','referrer_policy','x_content_type_options','permissions_policy'];
 if(x.headers && typeof x.headers==='object' && Object.hasOwn(x.headers,'csp_report_only'))headerKeys.push('csp_report_only');
 const h=record(x.headers,headerKeys);one(h.referrer_policy,['strict-origin-when-cross-origin','absent','unknown']);one(h.x_content_type_options,['nosniff','absent','unknown']);one(h.permissions_policy,states);
 const hs=record(h.hsts,['state','max_age_seconds','include_subdomains']);one(hs.state,states);if(hs.state==='present'){integer(hs.max_age_seconds,0,999999999999);one(hs.include_subdomains,[true,false,null]);}else if(hs.max_age_seconds!==null||hs.include_subdomains!==null)fail();
 for(const value of [h.csp,...(Object.hasOwn(h,'csp_report_only')?[h.csp_report_only]:[])]){const csp=record(value,['state','unsafe_inline','wildcard','location']);one(csp.state,states);one(csp.location,['unknown']);if(csp.state==='present'){one(csp.unsafe_inline,[true,false,null]);one(csp.wildcard,[true,false,null]);}else if(csp.unsafe_inline!==null||csp.wildcard!==null)fail();}
 const c=record(x.cookies,['count','secure','httponly','samesite_absent']);integer(c.count,0,1000);for(const k of ['secure','httponly','samesite_absent'])integer(c[k],0,c.count as number);
 return input as DiagnosticImport;
}
export function parseDiagnostic(text:string):DiagnosticImport {if(new TextEncoder().encode(text).length>MAX_IMPORT_BYTES)fail();let x:unknown;try{x=JSON.parse(text);rejectDuplicates(text);}catch{return fail();}return validateDiagnostic(x);}
