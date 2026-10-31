import {describe,it,expect} from 'vitest';
import * as report from './fortressReport';
it('never attributes a finding to an undeclared or unvalidated route',()=>{
 const finding={id:'hsts',status:'attention',severity:'low',route_index:4,route:'/PRIVATE_PATH'};
 const input={complete:false,requests_used:1,findings:[finding],route_execution:[{route_index:1,state:'completed'}]};
 for(const locale of ['en','fr'] as const){
  for(const scope of [{routes:['https://example.test/PRIVATE_PATH'],includeOrigin:false},undefined]){
   const html=report.renderFortressReport(input,locale,scope);
   expect(html).not.toContain('Route 4'); expect(html).not.toContain('PRIVATE_PATH');
   const article=new DOMParser().parseFromString(html,'text/html').querySelector('article')!;
   expect(article.textContent).toContain(locale==='fr'?'Indéterminé':'Indeterminate');
  }
 }
});
it('requires matching scope and valid execution for finding route attribution',()=>{
 const finding={id:'hsts',status:'attention',severity:'low',route_index:1,route:'/PRIVATE'};
 const scope={routes:['https://example.test/PRIVATE'],includeOrigin:false};
 const input={complete:false,requests_used:1,findings:[finding],route_execution:[{route_index:1,state:'completed'}]};
 const article=(data:unknown,s:typeof scope)=>new DOMParser().parseFromString(report.renderFortressReport(data,'en',s),'text/html').querySelector('article')!.textContent!;
 expect(article(input,scope)).toContain('Route 1 (declared)');
 for(const route_execution of [null,[],[{route_index:2,state:'completed'}],[{route_index:1,state:'completed'},{route_index:2,state:'not_started'}]]){
  const text=article({...input,route_execution},scope);expect(text).not.toContain('Route 1 (declared)');expect(text).toContain('Indeterminate');expect(text).not.toContain('PRIVATE');
 }
 expect(article(input,{routes:['invalid'],includeOrigin:false})).not.toContain('Route 1 (declared)');
});
it('accepts the narrow positive cookie code only for a conformant cookie finding',()=>{
 const findings=[{id:'cookie_attributes',status:'conformant',severity:'info',evidence_code:'cookie_attributes_present'}, {id:'cookie_attributes',status:'attention',severity:'low',evidence_code:'cookie_attributes_present'}, {id:'hsts',status:'conformant',severity:'info',evidence_code:'cookie_attributes_present'}];
 expect(report.safeFortressResult({complete:false,requests_used:1,findings}).findings.map(f=>f.evidence_code)).toEqual(['cookie_attributes_present','unknown','unknown']);
});
it('rejects evidence from invalid original tuples across repeated sanitization',()=>{
 const codes=['header_absent','header_present_unassessed','cookie_attributes_missing','tls_verified','http_plaintext','redirect_not_followed'];
 const findings=['hsts','cookie_attributes','https_tls','redirect'].flatMap(id=>['conformant','attention','suspected','confirmed','indeterminate','INVALID'].flatMap(status=>['info','low','medium','high','critical','unknown','INVALID'].flatMap(severity=>codes.map(evidence_code=>({id,status,severity,evidence_code})))));
 const validStatuses:Record<string,string[]>={hsts:['conformant','attention','indeterminate'],cookie_attributes:['conformant','attention','indeterminate'],https_tls:['conformant','indeterminate'],redirect:['conformant','confirmed','indeterminate']};
 const levels:Record<string,string>={conformant:'info',attention:'low',suspected:'medium',confirmed:'medium',indeterminate:'unknown'};
 const once=report.safeFortressResult({complete:false,requests_used:0,findings:findings.slice(0,100)});
 for(let start=0;start<findings.length;start+=100){
  const batch=findings.slice(start,start+100), safe=report.safeFortressResult({complete:false,requests_used:0,findings:batch}), twice=report.safeFortressResult(safe);
  batch.forEach((f,i)=>{if(!validStatuses[f.id].includes(f.status)||levels[f.status]!==f.severity){expect(safe.findings[i].evidence_code,JSON.stringify(f)).toBe('unknown');expect(twice.findings[i].evidence_code).toBe('unknown');}});
 }
 expect(once.findings.length).toBe(100);
});
it('reports missing recommended cookie attributes without asserting applicability in either language',()=>{
 const input={complete:false,requests_used:1,findings:[{id:'cookie_attributes',status:'attention',severity:'low',evidence_code:'cookie_attributes_missing'}]};
 for(const [locale,expected,unproven] of [['en','recommended attribute','applicability was not assessed'],['fr','attributs recommandés','applicabilité n’a pas été évaluée']] as const){
  const html=report.renderFortressReport(input,locale); expect(html).toContain(expected);expect(html).toContain(unproven);
 }
});
it('labels each route index as declared and execution as unavailable in both languages',()=>{
 const input={complete:false,requests_used:1,findings:[{id:'hsts',status:'indeterminate',severity:'unknown',route_index:2,route:'/private',execution_state:'observed'}]};
 for(const [locale,declared,unknown] of [['en','Route 2 (declared)','Per-route execution state unavailable'],['fr','Route 2 (déclarée)','État d’exécution par route indisponible']] as const){
  const html=report.renderFortressReport(input,locale,{routes:['https://example.test/','https://example.test/private'],includeOrigin:false});
  expect(html).toContain(declared); expect(html).toContain(unknown);expect(html).not.toContain('/private');
 }
});
it('distinguishes external guidance from observation provenance and severity rationale',()=>{
 const input={complete:true,requests_used:1,findings:[{id:'cors',status:'attention',severity:'low',evidence_code:'unknown',provenance:'PRIVATE',severity_rationale:'PRIVATE'}]};
 for(const [locale,guidance,provenance,rationale] of [['en','General guidance','Observation provenance','Severity rationale'],['fr','Référence générale','Provenance de l’observation','Justification de gravité']] as const){
  const doc=new DOMParser().parseFromString(report.renderFortressReport(input,locale),'text/html');const article=doc.querySelector('article')!;
  const fields=Object.fromEntries([...article.querySelectorAll('dt')].map(dt=>[dt.textContent,dt.nextElementSibling?.textContent]));
  expect(fields[guidance]).toContain('OWASP');expect(fields[provenance]?.toLowerCase()).toContain(locale==='en'?'unavailable':'indisponible');expect(fields[rationale]).toContain(locale==='en'?'not available':'non disponible');expect(article.textContent).not.toContain('PRIVATE');
 }
});
it('requires explicit true to export an identifying origin and excludes credentials and secret values',()=>{
 const input={complete:false,requests_used:0,findings:[{id:'hsts',status:'attention',severity:'low',evidence:'cookie=PRIVATE_VALUE'}]};
 for(const locale of ['en','fr'] as const){
  const routes=['https://person.example.test/private?token=PRIVATE_VALUE'];
  const implicit=report.renderFortressReport(input,locale,{routes,includeOrigin:'yes' as unknown as boolean});
  expect(implicit).not.toContain('person.example.test');expect(implicit).not.toContain('PRIVATE_VALUE');
  const explicit=report.renderFortressReport(input,locale,{routes,includeOrigin:true});expect(explicit).toContain('https://person.example.test');expect(explicit).not.toContain('PRIVATE_VALUE');expect(explicit).not.toContain('/private');
  expect(report.renderFortressReport(input,locale,{routes:['https://user:pass@person.example.test/'],includeOrigin:true})).not.toContain('person.example.test');
 }
});
describe('standalone fortress report',()=>{
 it('provides bilingual finding context without inventing evidence or severity rationale',()=>{
  const input={complete:false,requests_used:1,findings:[{id:'hsts',status:'attention',severity:'low',method:'GET',route:'[redacted route]',date:'2026-10-29'}]};
  for(const [locale,terms] of [['en',['Situation','Evidence','Indeterminate','Severity rationale','Preconditions','Remedy','Scope']],['fr',['Situation','Éléments de preuve','Indéterminé','Justification de gravité','Prérequis','Correction','Périmètre']]] as const){
   const html=report.renderFortressReport(input,locale);
   for(const term of terms) expect(html).toContain(term);
   expect(html).toContain('2026-10-29'); expect(html).toContain('GET');
   expect(html).not.toContain('policy_missing');
  }
 });
 it('exports a report renderer',()=>expect(report.renderFortressReport).toBeTypeOf('function'));
 it('explains reported classifications without converting them into observations',()=>{
  const input={complete:true,requests_used:1,findings:[{id:'hsts',status:'attention',severity:'low',method:'GET',route:'/'}]};
  for(const [locale,explanation] of [['en','The reported classification calls for review; it does not establish impact.'],['fr','La classification transmise appelle un examen ; elle ne démontre pas un impact.']] as const){
   const html=report.renderFortressReport(input,locale);
   expect(html).toContain(explanation);
   expect(html).toContain(locale==='fr'?'preuve structurée est non disponible':'structured evidence is not available');
  }
 });
 it('escapes untrusted text, redacts URL queries and has offline print styles',()=>{
  const result={audit_id:'<img src=x onerror=alert(1)>',mode:'deep',started_at:'now',finished_at:'now',scope:{origin:'https://example.test',paths:['/path?token=secret']},requests_used:1,complete:false,findings:[{id:'x',status:'attention' as const,severity:'low',reason:'<script>alert(1)</script>',evidence:'https://example.test/path?key=secret',limitations:'none',preconditions:'none',recommendation:'fix',reference:'OWASP',method:'GET',route:'/path?key=secret',date:'today'}],limitations:['bounded']};
  const html=report.renderFortressReport(result,'fr');
  expect(html).not.toContain('<script>');expect(html).not.toContain('secret');expect(html).not.toContain('&lt;script&gt;');expect(html).toContain('@media print');expect(html).toContain('default-src');expect(html).not.toMatch(/<(script|link|img)\b/i);expect(html).toContain('Rapport d’audit local');
 });
});

it('explains every accepted classification without presenting it as evidence',()=>{
 const findings=[{id:'hsts',status:'conformant',severity:'info'},{id:'hsts',status:'attention',severity:'low'},{id:'reflection',status:'suspected',severity:'medium'},{id:'redirect',status:'confirmed',severity:'medium'},{id:'version',status:'indeterminate',severity:'unknown'}];
 for(const locale of ['en','fr'] as const){
  const doc=new DOMParser().parseFromString(report.renderFortressReport({complete:false,requests_used:0,findings},locale),'text/html');
  expect(doc.querySelectorAll('article')).toHaveLength(findings.length);
  for(const a of doc.querySelectorAll('article')){
   const fields=[...a.querySelectorAll('dt')].map(dt=>dt.textContent);
   expect(fields).toContain(locale==='fr'?'Interprétation de la classification':'Classification meaning');
   expect(a.textContent).toContain(locale==='fr'?'preuve structurée est non disponible':'structured evidence is not available');
  }
 }
});

it('never exports arbitrary secret-bearing response fields',()=>{
 const secret='SENTINEL_SECRET';
 const r={audit_id:'Bearer '+secret,mode:'deep',started_at:'now',finished_at:'now',scope:{origin:'https://example.test/#'+secret,paths:['/api_key='+secret]},requests_used:1,complete:true,findings:[{id:'hsts',status:'attention' as const,severity:'low',reason:'Bearer '+secret,evidence:'Cookie: '+secret,limitations:'api_key='+secret,preconditions:secret,recommendation:secret,reference:secret,method:'GET',route:secret,date:secret}],limitations:[secret]};
 expect(report.renderFortressReport(r,'en')).not.toContain(secret);
});

it('rejects malformed envelopes rather than reporting zero or completion',()=>{
 expect(()=>report.safeFortressResult({complete:true,requests_used:'1',findings:[]})).toThrow();
 expect(()=>report.safeFortressResult({complete:'yes',requests_used:1,findings:[]})).toThrow();
 expect(()=>report.safeFortressResult({complete:true,requests_used:1,findings:Array(101).fill({})})).toThrow();
});

it('keeps only bounded context through the UI sanitization and export boundaries',()=>{
 const input={complete:true,requests_used:3,mode:'deep',findings:[{id:'reflection',status:'suspected',severity:'medium',method:'GET',route:'/person?secret=PRIVATE',date:'2026-02-29',reference:'https://evil.test/PRIVATE',evidence:'<img src=x onerror=PRIVATE>',reason:'PRIVATE',extra:'PRIVATE'}]};
 const safe=report.safeFortressResult(input);
 expect(safe.findings[0]).toEqual({id:'reflection',status:'suspected',severity:'medium',method:'GET',route:'[redacted route]',route_index:null,evidence_code:'unknown',date:'unknown'});
 for(const locale of ['en','fr'] as const){
  const html=report.renderFortressReport(safe,locale);
  expect(html).not.toContain('PRIVATE'); expect(html).not.toContain('evil.test'); expect(html).not.toContain('2026-02-29');
  expect(html).toContain('[redacted route]'); expect(html).toContain('GET');
  expect(html).not.toMatch(/<(script|img|link|iframe|object)\b/i);
  const doc=new DOMParser().parseFromString(html,'text/html');
  expect([...doc.querySelectorAll('a')].map(a=>a.getAttribute('href'))).toEqual(['https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/']);
  expect(doc.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute('content')).toContain("connect-src 'none'");
 }
});

it('provides static bilingual topics for every established id, without treating statuses as facts',()=>{
 const ids=['https_tls','hsts','csp','x_content_type_options','referrer_policy','permissions_policy','cookie_attributes','third_party_scripts','version','debug_info','directory_index','cors','redirect','reflection'];
 const input={complete:false,requests_used:0,findings:ids.map(id=>({id,status:'indeterminate',severity:'unknown'}))};
 for(const locale of ['en','fr'] as const){
  const doc=new DOMParser().parseFromString(report.renderFortressReport(input,locale),'text/html');
  expect(doc.querySelectorAll('article')).toHaveLength(ids.length);
  for(const article of doc.querySelectorAll('article')) expect(article.textContent).toContain(locale==='fr'?'Indéterminé':'Indeterminate');
 }
});


it('downgrades unsupported rule status severity triples without echoing input',()=>{
 const findings=[{id:'reflection',status:'confirmed',severity:'critical'},{id:'version',status:'conformant',severity:'info'},{id:'https_tls',status:'attention',severity:'low'},{id:'hsts',status:'attention',severity:'critical'},{id:'redirect',status:'confirmed',severity:'medium'},{id:'cors',status:'suspected',severity:'medium'},{id:'hsts',status:'PRIVATE',severity:'PRIVATE'}];
 const safe=report.safeFortressResult({complete:true,requests_used:1,findings});
 expect(safe.findings.map(f=>[f.status,f.severity])).toEqual([['indeterminate','unknown'],['indeterminate','unknown'],['indeterminate','unknown'],['indeterminate','unknown'],['confirmed','medium'],['suspected','medium'],['indeterminate','unknown']]);
 expect(report.renderFortressReport({complete:true,requests_used:1,findings},'en')).not.toContain('PRIVATE');
});

it('does not claim discarded evidence was absent or assert unobserved control requirements',()=>{
 const findings=['redirect','reflection'].map(id=>({id,status:'conformant',severity:'info',evidence:{fact:'PRIVATE'}}));
 for(const locale of ['en','fr'] as const){
  const html=report.renderFortressReport({complete:true,requests_used:1,findings},locale);
  expect(html).not.toContain('PRIVATE');
  expect(html).toContain(locale==='en'?'not available in this report':'non disponible dans ce rapport');
  expect(html).toContain(locale==='en'?'may require':'peut nécessiter');
  expect(html).not.toContain('no structured evidentiary fact supplied');
  expect(html).not.toContain('aucun fait probant structuré fourni');
 }
});


it('accepts only evaluator-defined status and severity combinations for each rule',()=>{
 const allowed:Record<string,string[]>={https_tls:['conformant'],hsts:['conformant','attention'],csp:['conformant','attention'],x_content_type_options:['conformant','attention'],referrer_policy:['conformant','attention'],permissions_policy:['conformant','attention'],cookie_attributes:['conformant','attention'],third_party_scripts:['conformant','attention'],version:[],debug_info:['conformant','attention'],directory_index:['conformant','attention'],cors:['conformant','attention','suspected'],redirect:['conformant','confirmed'],reflection:['conformant','suspected']};
 const severity:Record<string,string>={conformant:'info',attention:'low',suspected:'medium',confirmed:'medium',indeterminate:'unknown'};
 for(const [id,permitted] of Object.entries(allowed)) for(const status of Object.keys(severity)) for(const level of ['info','low','medium','high','critical','unknown','PRIVATE']){
  const f=report.safeFortressResult({complete:false,requests_used:0,findings:[{id,status,severity:level}]}).findings[0];
  const valid=(status==='indeterminate'||permitted.includes(status))&&severity[status]===level;
  expect([f.status,f.severity],id+'/'+status+'/'+level).toEqual(valid?[status,level]:['indeterminate','unknown']);
 }
});


it('preserves typed evidence across repeated sanitization and rejects incompatible claims',()=>{
 const input={complete:true,requests_used:1,findings:[{id:'hsts',status:'attention',severity:'low',evidence_code:'header_absent',route_index:1},{id:'hsts',status:'conformant',severity:'info',evidence_code:'header_present_unassessed',route_index:2},{id:'https_tls',status:'conformant',severity:'info',evidence_code:'tls_verified',route_index:3}]};
 const safe=report.safeFortressResult(report.safeFortressResult(input));
 expect(safe.findings.map(f=>f.evidence_code)).toEqual(['header_absent','unknown','tls_verified']);
 const html=report.renderFortressReport(safe,'en');
 expect(html).toContain('Header absent'); expect(html).toContain('TLS verification succeeded'); expect(html).not.toContain('Route 1');
});


it('discloses only an explicitly selected operator origin and route indexes',()=>{
 const input={complete:true,requests_used:1,findings:[]};
 const html=report.renderFortressReport(input,'fr',{routes:['https://example.test/person/PRIVATE?token=SECRET','https://example.test/other'],includeOrigin:true});
 expect(html).toContain('https://example.test'); expect(html).toContain('Route 1'); expect(html).toContain('Route 2');
 expect(html).not.toContain('PRIVATE');expect(html).not.toContain('SECRET');expect(html).not.toContain('/other');
 const hidden=report.renderFortressReport(input,'en',{routes:['https://example.test/person/PRIVATE'],includeOrigin:false});
 expect(hidden).not.toContain('example.test'); expect(hidden).toContain('Route 1');
});


it('renders each supported evidence code in both languages without admitting arbitrary text',()=>{
 const findings=[{id:'hsts',status:'attention',severity:'low',evidence_code:'header_absent'},{id:'csp',status:'indeterminate',severity:'unknown',evidence_code:'header_present_unassessed'},{id:'cookie_attributes',status:'attention',severity:'low',evidence_code:'cookie_attributes_missing'},{id:'https_tls',status:'conformant',severity:'info',evidence_code:'tls_verified'},{id:'https_tls',status:'indeterminate',severity:'unknown',evidence_code:'http_plaintext'},{id:'redirect',status:'indeterminate',severity:'unknown',evidence_code:'redirect_not_followed'},{id:'hsts',status:'attention',severity:'low',evidence_code:'<script>PRIVATE</script>',route_index:999}];
 for(const [locale,terms] of [['en',['Header absent','Header present','cookie lacks','TLS verification succeeded','Plain HTTP','redirect was not followed']],['fr',['En-tête absent','En-tête présent','cookie ne possède','vérification TLS','HTTP en clair','redirection n’a pas été suivie']]] as const){
  const html=report.renderFortressReport({complete:true,requests_used:1,findings},locale);
  for(const term of terms) expect(html).toContain(term);
  expect(html).not.toContain('PRIVATE'); expect(html).not.toContain('Route 999');expect(html).toContain('@media(max-width:600px)');
 }
});

it('renders only strictly validated route execution, never route paths',()=>{
 const input={complete:false,requests_used:1,findings:[],route_execution:[{route_index:1,state:'completed'},{route_index:2,state:'not_started'}]};
 const html=report.renderFortressReport(input,'fr',{routes:['https://private.test/secret','https://private.test/person'],includeOrigin:false});
 expect(html).toContain('Observation directe terminée');expect(html).toContain('Non démarrée');expect(html).not.toContain('private.test');expect(html).not.toContain('/secret');
 const bad=report.renderFortressReport({...input,route_execution:[{route_index:1,state:'<secret>'}]},'fr');
 expect(bad).not.toContain('&lt;secret&gt;');expect(bad).toContain('État d’exécution par route indisponible');
});
