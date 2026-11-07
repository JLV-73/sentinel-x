import {it,expect} from 'vitest';
import {renderFortressReport} from './fortressReport';
const result={mode:'fixture',target:'https://standard-lab.invalid/',route:'/',scenario:'ok',generated_at:'2026-11-05T12:00:00+00:00',http_status:200,failure_code:'none',tls:{},headers:{},cookies:{},findings:[],limits:[]};
it('shows declared fixture target, route and date in both languages',()=>{
 for(const locale of ['fr','en'] as const){const html=renderFortressReport(result,locale);expect(html).toContain('https://standard-lab.invalid/');expect(html).toContain('2026-11-05T12:00:00+00:00');expect(html).toContain('>/</strong>');}
});
it('never renders forged or sensitive target or route',()=>{
 for(const target of ['https://evil.invalid/private?secret=token','https://user:secret@standard-lab.invalid/','https://standard-lab.invalid/#secret',undefined]){
  const html=renderFortressReport({...result,target,route:'/secret'},'fr');expect(html).not.toContain('secret');expect(html).not.toContain('evil.invalid');expect(html).not.toContain('https://standard-lab.invalid/');
 }
});
it('reports an unestablished TLS/transport cause without inventing a hostname failure or GET stage',()=>{
 for(const locale of ['fr','en'] as const){
  const html=renderFortressReport({...result,scenario:'tls-error',http_status:null,failure_code:'tls_or_transport'},locale);
  expect(html).toContain(locale==='fr'?'Erreur TLS/transport : la cause précise n’est pas établie.':'TLS/transport error: the precise cause is not established.');
  expect(html).not.toMatch(/hostname mismatch|nom d’hôte incorrect/i);
  expect(html).not.toMatch(/no GET (?:was sent|sent|observed)|GET (?:was not|not) sent|aucun GET (?:envoyé|observé)/i);
 }
});
