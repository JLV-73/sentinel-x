import {describe,it,expect} from 'vitest';
import {renderFortressReport} from './fortressReport';

describe('final fidelity',()=>{
 it('does not invent TLS cause or GET stage',()=>{
  for(const locale of ['fr','en'] as const){
   const html=renderFortressReport({mode:'fixture',route:'/',target:'https://standard-lab.invalid/',scenario:'tls-error',failure_code:'tls_or_transport'},locale);
   expect(html).not.toMatch(/hostname mismatch|nom d’hôte incorrect|no GET observed|aucun GET observé/i);
   expect(html).toMatch(/cause précise.*établie|precise cause.*established/i);
  }
 });
 it('explains observed disabled HSTS and active CSP',()=>{
  const input={mode:'fixture',route:'/',target:'https://standard-lab.invalid/',scenario:'ok',failure_code:'none',http_status:200,headers:{hsts:'present',csp:'present'},security_details:{hsts:{status:'disabled',seconds:0},csp:{status:'present',directives:[{directive:'script-src',inline:true,wildcard:'any'}]},csp_report_only:{status:'missing',directives:[]}}};
  const html=renderFortressReport(input,'en');
  expect(html).toMatch(/disables.*cached/i); expect(html).toContain('script-src'); expect(html).toContain('unsafe-inline');
 });
});
