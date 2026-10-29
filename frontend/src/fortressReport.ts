import type {Locale} from './i18n';
// Only fixed vocabulary and bounded numbers cross the untrusted response boundary.
const ids = ['https_tls','hsts','csp','x_content_type_options','referrer_policy','permissions_policy','cookie_attributes','third_party_scripts','version','debug_info','directory_index','cors','redirect','reflection'] as const;
const statuses = ['conformant','attention','suspected','confirmed','indeterminate'] as const;
const severities = ['info','low','medium','high','critical','unknown'] as const;
type Status = typeof statuses[number];
type Severity = typeof severities[number];
type Method = 'GET'|'HEAD'|'OPTIONS'|'unknown';
type Route = '/'|'[redacted route]'|'unknown';
export type SafeFortressResult = {complete:boolean; requests_used:number; mode:'standard'|'deep'|'unknown'; findings:{id:string;status:Status;severity:Severity;method:Method;route:Route;date:string}[]};
const safeDate = (v:unknown):string => {
 if(typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return 'unknown';
 const d=new Date(v+'T00:00:00Z');
 return Number.isFinite(d.getTime()) && d.toISOString().slice(0,10)===v ? v : 'unknown';
};
const member = <T extends string>(values:readonly T[], value:unknown):value is T => typeof value === 'string' && values.includes(value as T);
// These are possible evaluator outputs, not verification of the underlying facts.
const ruleStatuses:Record<typeof ids[number],readonly Status[]> = {
 https_tls:['conformant','indeterminate'], hsts:['conformant','attention','indeterminate'], csp:['conformant','attention','indeterminate'],
 x_content_type_options:['conformant','attention','indeterminate'], referrer_policy:['conformant','attention','indeterminate'], permissions_policy:['conformant','attention','indeterminate'],
 cookie_attributes:['conformant','attention','indeterminate'], third_party_scripts:['conformant','attention','indeterminate'], version:['indeterminate'],
 debug_info:['conformant','attention','indeterminate'], directory_index:['conformant','attention','indeterminate'], cors:['conformant','attention','suspected','indeterminate'],
 redirect:['conformant','confirmed','indeterminate'], reflection:['conformant','suspected','indeterminate']
};
const ruleSeverity:Record<Status,Severity> = {conformant:'info',attention:'low',suspected:'medium',confirmed:'medium',indeterminate:'unknown'};
export function safeFortressResult(input:unknown):SafeFortressResult {
 const x = input && typeof input === 'object' && !Array.isArray(input) ? input as Record<string,unknown> : {};
 if (typeof x.complete !== 'boolean' || typeof x.requests_used !== 'number' || !Number.isInteger(x.requests_used) || x.requests_used < 0 || x.requests_used > 30 || !Array.isArray(x.findings) || x.findings.length > 100) throw new Error('Invalid audit result');
 const findings = x.findings.flatMap((value:unknown) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  const f = value as Record<string,unknown>;
  if (!member(ids,f.id)) return [];
  const valid = member(statuses,f.status) && member(severities,f.severity) && ruleStatuses[f.id].includes(f.status) && ruleSeverity[f.status] === f.severity;
  const status:Status = valid ? f.status as Status : 'indeterminate';
  const severity:Severity = valid ? f.severity as Severity : 'unknown';
  const method:Method = member(['GET','HEAD','OPTIONS'] as const,f.method) ? f.method : 'unknown';
  const route:Route = f.route === '/' ? '/' : typeof f.route === 'string' && f.route !== 'unknown' ? '[redacted route]' : 'unknown';
  return [{id:f.id,status,severity,method,route,date:safeDate(f.date)}];
 });
 return {complete:x.complete, requests_used:x.requests_used, mode:x.mode==='standard'||x.mode==='deep'?x.mode:'unknown', findings};
}
const statusLabels:Record<Status,[string,string]> = {conformant:['Conformant','Conforme'],attention:['Attention','Attention'],suspected:['Suspected','Suspecté'],confirmed:['Confirmed non-destructively','Confirmé sans destruction'],indeterminate:['Indeterminate','Indéterminé']};
const severityLabels:Record<Severity,[string,string]> = {info:['Informational','Information'],low:['Low','Faible'],medium:['Medium','Moyenne'],high:['High','Élevée'],critical:['Critical','Critique'],unknown:['Unreported','Non renseignée']};
export const fortressStatus = (s:Status, locale:Locale) => statusLabels[s][locale === 'fr' ? 1 : 0];
export const fortressSeverity = (s:Severity, locale:Locale) => severityLabels[s][locale === 'fr' ? 1 : 0];
const escape=(value:string)=>value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]||c));
type Pair = readonly [string,string];
type Topic = {name:Pair; remedy:Pair; limit?:Pair; precondition?:Pair; source?:string};
const topics:Record<typeof ids[number],Topic> = {
 https_tls:{name:['HTTPS and verified TLS','HTTPS et TLS vérifié'],remedy:['Review HTTPS and certificate configuration.','Vérifier HTTPS et la configuration du certificat.']},
 hsts:{name:['HTTP Strict Transport Security','HTTP Strict Transport Security'],remedy:['Review the intended HSTS policy.','Vérifier la politique HSTS prévue.']},
 csp:{name:['Content Security Policy','Politique de sécurité du contenu'],remedy:['Review the content security policy.','Vérifier la politique de sécurité du contenu.']},
 x_content_type_options:{name:['Content type sniffing protection','Protection contre la détection du type de contenu'],remedy:['Review the nosniff policy.','Vérifier la politique nosniff.']},
 referrer_policy:{name:['Referrer policy','Politique de référent'],remedy:['Review the referrer policy.','Vérifier la politique de référent.']},
 permissions_policy:{name:['Permissions policy','Politique de permissions'],remedy:['Review the permissions policy.','Vérifier la politique de permissions.']},
 cookie_attributes:{name:['Cookie attributes','Attributs des cookies'],remedy:['Review applicable Secure, HttpOnly and SameSite attributes.','Vérifier les attributs Secure, HttpOnly et SameSite applicables.'],limit:['Applicability depends on cookie use; values are excluded.','La pertinence dépend de l’usage des cookies ; les valeurs sont exclues.']},
 third_party_scripts:{name:['Third-party script declarations','Déclarations de scripts tiers'],remedy:['Review declared script origins and necessity.','Vérifier les origines et la nécessité des scripts déclarés.'],limit:['A declaration does not establish script safety.','Une déclaration ne démontre pas la sûreté du script.']},
 version:{name:['Component and advisory assessment','Évaluation des composants et avis'],remedy:['Verify component identity and consult appropriate reviewed advisories.','Vérifier l’identité du composant et consulter les avis pertinents examinés.'],limit:['Advisory matching is unavailable; no vulnerability conclusion is established.','La comparaison aux avis est indisponible ; aucune conclusion de vulnérabilité n’est établie.']},
 debug_info:{name:['Debug information indicators','Indicateurs de débogage'],remedy:['Review production debug exposure.','Vérifier l’exposition du débogage en production.']},
 directory_index:{name:['Directory index indicators','Indicateurs d’index de répertoire'],remedy:['Review directory listing configuration.','Vérifier la configuration des listes de répertoires.']},
 cors:{name:['Cross-origin resource sharing','Partage de ressources entre origines'],remedy:['Review allowed origins and credentials policy.','Vérifier les origines autorisées et la politique d’identifiants.'],limit:['Permissiveness alone does not demonstrate access to sensitive data.','Une politique permissive ne démontre pas à elle seule l’accès à des données sensibles.'],precondition:['Impact depends on browser behavior, response content and credentials policy.','L’impact dépend du navigateur, du contenu de la réponse et de la politique d’identifiants.'],source:'https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/'},
 redirect:{name:['Redirect behavior','Comportement de redirection'],remedy:['Review and restrict redirect destinations.','Vérifier et limiter les destinations de redirection.'],limit:['A witness alone does not establish attribution or broader compromise.','Un témoin seul ne démontre ni attribution ni compromission générale.'],precondition:['Assessment may require an authorized parameter and a comparable control; whether they were used is not available in this report.','L’évaluation peut nécessiter un paramètre autorisé et un contrôle comparable ; leur utilisation est non disponible dans ce rapport.'],source:'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'},
 reflection:{name:['Inert input reflection','Réflexion d’une entrée inerte'],remedy:['Review context-sensitive output encoding and input handling.','Vérifier l’encodage des sorties selon leur contexte et le traitement des entrées.'],limit:['Reflection alone does not prove XSS or execution.','La réflexion seule ne prouve ni XSS ni exécution.'],precondition:['Assessment may require an authorized parameter and an inert marker; whether they were used is not available in this report.','L’évaluation peut nécessiter un paramètre autorisé et un marqueur inerte ; leur utilisation est non disponible dans ce rapport.'],source:'https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/'}
};
export function renderFortressReport(input:unknown, locale:Locale):string {
 const result=safeFortressResult(input), fr=locale==='fr', text=(pair:Pair)=>escape(pair[fr?1:0]);
 const unknown=fr?'Indéterminé':'Indeterminate';
 const field=(label:Pair,value:string)=>`<div><dt>${text(label)}</dt><dd>${value}</dd></div>`;
 const findings=result.findings.map(f=>{
  const topic=topics[f.id as typeof ids[number]];
  const source=topic.source ? `<a href="${escape(topic.source)}" rel="noopener noreferrer">OWASP</a>` : unknown;
  return `<article><h3>${text(topic.name)} <small>${escape(f.id)}</small></h3><dl>${field(['Situation','Situation'],`${escape(fortressStatus(f.status,locale))} — ${fr?'classification transmise, non vérifiée ici':'reported classification, not independently verified here'}`)}${field(['Severity','Gravité'],escape(fortressSeverity(f.severity,locale)))}${field(['Severity rationale','Justification de gravité'],fr?'Indéterminé : la justification structurée est non disponible dans ce rapport ; la gravité transmise ne mesure pas l’impact.':'Indeterminate: structured rationale is not available in this report; reported severity does not measure impact.')}${field(['Evidence','Éléments de preuve'],fr?'Indéterminé : la preuve structurée est non disponible dans ce rapport ; le statut seul ne constitue pas une preuve.':'Indeterminate: structured evidence is not available in this report; status alone is not evidence.')}${field(['Scope / method / date','Périmètre / méthode / date'],`${escape(f.route==='unknown'?unknown:f.route)} · ${escape(f.method==='unknown'?unknown:f.method)} · ${escape(f.date==='unknown'?unknown:f.date)}`)}${field(['Limits','Limites'],text(topic.limit || ['This check cannot establish overall security.','Ce contrôle ne démontre pas la sécurité globale.']))}${field(['Preconditions','Prérequis'],text(topic.precondition || ['Impact depends on actual configuration and context; these are indeterminate here.','L’impact dépend de la configuration et du contexte réels ; ils sont indéterminés ici.']))}${field(['Remedy','Correction'],text(topic.remedy))}${field(['Source','Source'],source)}</dl></article>`;
 }).join('');
 return `<!doctype html><html lang="${fr?'fr':'en'}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'"><meta name="viewport" content="width=device-width, initial-scale=1"><title>DIGITAL FORTRESS</title><style>:root{color-scheme:dark}body{font:16px/1.55 system-ui,sans-serif;background:#101722;color:#e6edf5;margin:0;padding:2rem}main{max-width:980px;margin:auto}article{background:#162232;border:1px solid #38516b;border-radius:8px;padding:1.2rem;margin:1rem 0;break-inside:avoid}h1,h2,h3{color:#9de5e2}small{color:#b9c8d7}dt{font-weight:700;color:#b6d7e4}dd{margin:0 0 .8rem}a{color:#9de5e2;overflow-wrap:anywhere}@media print{:root{color-scheme:light}body,article{background:white;color:black}h1,h2,h3,dt,a{color:black}article{border:1px solid #777}small{color:#333}}</style></head><body><main><h1>DIGITAL FORTRESS</h1><p>${fr?'Rapport d’audit local':'Local audit report'}</p><h2>${fr?'Situation et périmètre':'Situation and Scope'}</h2><p>${fr?'Requêtes':'Requests'}: ${result.requests_used} · ${result.complete?(fr?'Terminé selon le résultat':'Complete according to result'):(fr?'Incomplet':'Incomplete')} · Mode: ${escape(result.mode==='unknown'?unknown:result.mode)}</p><p>${fr?'Résumé incomplet : les preuves structurées et leur provenance ne sont pas disponibles. Aucune certification ni note globale. Les chemins et les données du serveur sont omis ; la correspondance des routes et paramètres reste chez l’opérateur. Les requêtes peuvent être journalisées par la cible. Les contrôles absents, inconnus ou non effectués restent indéterminés.':'Incomplete summary: structured evidence and provenance are unavailable. No certification or global grade. Paths and server data are omitted; the operator retains the route and parameter mapping. Requests may be logged by the target. Missing, unknown or unperformed checks remain indeterminate.'}</p><p>${fr?'Technique : contrôles autorisés à faible impact ; les opérations réellement effectuées sont indéterminées sans faits structurés.':'Technique: authorized low-impact checks; operations actually performed are indeterminate without structured facts.'}</p><h2>${fr?'Constats':'Findings'}</h2>${findings || `<p>${unknown}</p>`}<p>${fr?'Les liens OWASP sont des références générales ouvertes uniquement sur action de l’utilisateur.':'OWASP links are background references opened only by user action.'}</p></main></body></html>`;
}
