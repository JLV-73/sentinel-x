import {describe,it,expect} from 'vitest';
import * as report from './fortressReport';
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
 expect(safe.findings[0]).toEqual({id:'reflection',status:'suspected',severity:'medium',method:'GET',route:'[redacted route]',date:'unknown'});
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
