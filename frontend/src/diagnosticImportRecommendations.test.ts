import {describe,it,expect} from 'vitest';
import {parseDiagnostic} from './diagnosticImport';
import {renderFortressReport} from './fortressReport';
const fixture=()=>({mode:'import',version:1,provenance:'report_transcription',target:'https://example.org/',observed_at:'2025-01-15T12:00:00+01:00',method:'GET',scope:'root_only',http_status:200,tls:{protocol:'TLSv1.3',certificate:'verified',hostname:'verified',not_before:null,not_after:null,revocation:'not_checked'},headers:{hsts:{state:'present',max_age_seconds:0,include_subdomains:false},csp:{state:'present',unsafe_inline:false,wildcard:false,location:'unknown'},csp_report_only:{state:'present',unsafe_inline:true,wildcard:true,location:'unknown'},referrer_policy:'unknown',x_content_type_options:'unknown',permissions_policy:'unknown'},cookies:{count:1,secure:1,httponly:1,samesite_absent:0}});
const render=(x:unknown,lang:'fr'|'en')=>renderFortressReport(parseDiagnostic(JSON.stringify(x)),lang);
describe('import fidelity',()=>{
 it('keeps Report-Only separate and never flags active CSP when both indicators are false',()=>{for(const lang of ['fr','en'] as const){const html=render(fixture(),lang);expect(html).toContain('CSP Report-Only');expect(html).toContain(lang==='fr'?'non appliquée':'not enforced');expect(html).toContain(lang==='fr'?'effacer la politique mémorisée':'clear the cached policy');expect(html).not.toContain(lang==='fr'?'CSP active : expressions signalées':'Active CSP: flagged expressions');expect(html).not.toContain(lang==='fr'?'Examiner SameSite':'Review SameSite');}});
 it('rejects unknown report-only keys and unsafe values without rendering them',()=>{const x:any=fixture();x.headers.csp_report_only.injected='<script>attack()</script>';expect(()=>parseDiagnostic(JSON.stringify(x))).toThrow();expect(renderFortressReport(x,'fr')).not.toContain('attack()');});
 it('accepts legacy v1 and marks omitted report-only unknown',()=>{const x:any=fixture();delete x.headers.csp_report_only;expect(render(x,'en')).toContain('CSP Report-Only');expect(render(x,'en')).toContain('indeterminate');});
 it('handles HSTS, CSP and SameSite alternatives in both languages',()=>{for(const lang of ['fr','en'] as const){const x:any=fixture();x.headers.hsts.max_age_seconds=60;x.headers.csp.unsafe_inline=true;x.cookies.samesite_absent=1;let html=render(x,lang);expect(html).toContain(lang==='fr'?'durée positive déclarée':'positive duration declared');expect(html).toContain(lang==='fr'?'CSP active : expressions signalées':'Active CSP: flagged expressions');expect(html).toContain(lang==='fr'?'Examiner SameSite':'Review SameSite');for(const state of ['absent','unknown']){x.headers.hsts={state,max_age_seconds:null,include_subdomains:null};x.headers.csp={state,unsafe_inline:null,wildcard:null,location:'unknown'};html=render(x,lang);expect(html).toContain(state==='absent'?'HSTS absent':(lang==='fr'?'HSTS indéterminé':'HSTS indeterminate'));expect(html).toContain(state==='absent'?(lang==='fr'?'CSP active absente':'Active CSP absent'):(lang==='fr'?'CSP active indéterminée':'Active CSP indeterminate'));}}});
 it('validates and renders both synthetic samples',()=>{
  const legacy:{headers:{csp_report_only?:unknown}}=fixture();
  delete legacy.headers.csp_report_only;
  const samples=[{input:legacy,reportOnly:false},{input:fixture(),reportOnly:true}];
  for(const {input,reportOnly} of samples){
   expect(Object.hasOwn(input.headers,'csp_report_only')).toBe(reportOnly);
   const d=parseDiagnostic(JSON.stringify(input));
   expect(d.observed_at).toBe('2025-01-15T12:00:00+01:00');
   if(reportOnly)expect(d.headers.csp_report_only).toEqual({state:'present',unsafe_inline:true,wildcard:true,location:'unknown'});
   else expect(d.headers.csp_report_only).toBeUndefined();
   for(const lang of ['fr','en'] as const){
    const html=renderFortressReport(d,lang);
    expect(html).toContain('2025-01-15T12:00:00+01:00');
    expect(html).toContain('CSP Report-Only');
    expect(html).toContain(lang==='fr'?'Diagnostic externe importé':'Imported external diagnostic');
   }
  }
 });
});
