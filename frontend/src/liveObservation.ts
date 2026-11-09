import type {Locale} from './i18n';
export type State='present'|'absent'|'indeterminate';
export type Observation={mode:'live';target:string;observed_at:string;http_status:number|null;tls:{certificate:'verified'|'indeterminate';hostname:'verified'|'indeterminate';protocol:string|null;not_before:string|null;not_after:string|null};headers:Record<'hsts'|'csp'|'x_content_type_options'|'referrer_policy'|'permissions_policy',State>;failure_code:'none'|'http_refused'|'timeout'|'tls_or_transport'|'blocked'|'incomplete'|'unknown'};
const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:Record<string,unknown>,ks:string[])=>Object.keys(v).length===ks.length&&ks.every(k=>Object.hasOwn(v,k));
const utc=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(v)&&!Number.isNaN(Date.parse(v));
const certDate=(v:unknown)=>v===null||(typeof v==='string'&&v.length<=40&&/^[A-Z][a-z]{2} {1,2}\d{1,2} \d\d:\d\d:\d\d \d{4} GMT$/.test(v)&&!Number.isNaN(Date.parse(v)));
export function validInput(value:string):boolean {try{const u=new URL(value);return value===value.trim()&&u.protocol==='https:'&&!!u.hostname&&!u.username&&!u.password&&!u.hash;}catch{return false;}}
export function parseObservation(raw:unknown,input:string):Observation {
 const fail=():never=>{throw new Error('invalid');};
 if(!validInput(input)||!obj(raw)||!keys(raw,['mode','target','observed_at','http_status','tls','headers','failure_code'])||raw.mode!=='live'||typeof raw.target!=='string')return fail();
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
 return raw as Observation;
}
const esc=(v:string)=>v.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
export function renderLiveReport(o:Observation,locale:Locale):string {
 const fr=locale==='fr',unknown=fr?'Indéterminé':'Indeterminate';
 const state=(s:string)=>({present:fr?'Présent':'Present',absent:fr?'Absent':'Absent',indeterminate:unknown,verified:fr?'Vérifié':'Verified'} as Record<string,string>)[s]??unknown;
 const reasons:Record<Observation['failure_code'],string>=fr?{none:'Aucun',http_refused:'Réponse HTTP non favorable',tls_or_transport:'Erreur TLS ou transport',timeout:'Délai dépassé',blocked:'Bloqué',incomplete:'Réponse incomplète',unknown:'Inconnu'}:{none:'None',http_refused:'Unfavourable HTTP response',tls_or_transport:'TLS or transport error',timeout:'Timed out',blocked:'Blocked',incomplete:'Incomplete response',unknown:'Unknown'};
 const rows=Object.entries(o.headers).map(([k,v])=>`<li>${esc(k.replaceAll('_','-'))} : ${esc(state(v))}</li>`).join('');
 return `<!doctype html><html lang="${locale}"><head><meta charset="utf-8"><title>${fr?'Observation HTTPS':'HTTPS observation'}</title><style>body{font:16px/1.6 system-ui;max-width:850px;margin:2rem auto;padding:0 1rem;color:#192237}h1,h2{color:#203c63}li{margin:.3rem 0}</style></head><body><h1>${fr?'Observation HTTPS réelle':'Live HTTPS observation'}</h1><p>${fr?'Provenance : tentative d’observation HTTPS HEAD. Redirections non suivies. Chemin et paramètres masqués. Aucun scan de vulnérabilités.':'Provenance: HTTPS HEAD observation attempt. Redirects not followed. Path and query masked. No vulnerability scan.'}</p><p>${fr?'Cible':'Target'} : ${esc(o.target)}<br>UTC : ${esc(o.observed_at)}<br>HTTP : ${o.http_status??unknown}<br>${fr?'Cause':'Reason'} : ${esc(reasons[o.failure_code])}</p><h2>TLS</h2><p>${fr?'Certificat':'Certificate'} : ${state(o.tls.certificate)}<br>${fr?'Nom d’hôte':'Hostname'} : ${state(o.tls.hostname)}<br>${fr?'Protocole':'Protocol'} : ${esc(o.tls.protocol??unknown)}<br>${fr?'Validité':'Validity'} : ${esc(o.tls.not_before??unknown)} — ${esc(o.tls.not_after??unknown)}</p><h2>${fr?'Constats sur les en-têtes':'Header observations'}</h2><ul>${rows}</ul><h2>${fr?'Limites et recommandations':'Limitations and recommendations'}</h2><p>${fr?'La présence ne démontre ni conformité ni efficacité ; les valeurs et leur configuration ne sont pas évaluées. Une absence observée mérite une vérification dans le contexte du service. Pour les états indéterminés ou les erreurs, vérifier la connectivité et renouveler uniquement avec autorisation.':'Presence does not establish compliance or effectiveness; values and configuration are not assessed. An observed absence warrants review in the service context. For indeterminate states or errors, check connectivity and retry only with authorization.'}</p></body></html>`;
}
