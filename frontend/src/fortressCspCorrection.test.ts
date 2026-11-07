import {describe,it,expect} from 'vitest';
import {renderFortressReport} from './fortressReport';

type Directive={directive:string;inline:boolean;wildcard:'none'|'any'|'domain'};
const d=(directive:string,inline=false,wildcard:Directive['wildcard']='none'):Directive=>({directive,inline,wildcard});
function report(directives:Directive[], locale:'fr'|'en', reportOnly=false) {
 const present={status:'present',directives}, missing={status:'missing',directives:[]};
 return renderFortressReport({mode:'fixture',route:'/',target:'https://standard-lab.invalid/',scenario:'ok',failure_code:'none',http_status:200,headers:{csp:reportOnly?'absent':'present'},security_details:{csp:reportOnly?missing:present,csp_report_only:reportOnly?present:missing}},locale);
}
describe.each(['fr','en'] as const)('CSP contextual semantics %s',locale=>{
 it('identifies image expression as inapplicable without script nonce advice',()=>{
  const html=report([d('img-src',true)],locale);
  expect(html).toMatch(/img-src.*(?:inapplicable|not applicable)/i);
  expect(html).not.toMatch(/nonces ou empreintes|nonces or hashes/i);
 });
 it('explains default fallback is overridden independently',()=>{
  const html=report([d('default-src',true),d('script-src'),d('style-src')],locale);
  expect(html).toMatch(/default-src : unsafe-inline/);
  expect(html).toMatch(/script-src.*(?:prévaut|overrides)/i);
  expect(html).toMatch(/style-src.*(?:prévaut|overrides)/i);
  expect(html).not.toMatch(/nonces ou empreintes|nonces or hashes/i);
 });
 it('gives contextual advice for direct script and style, with uncertainty',()=>{
  for (const name of ['script-src','style-src']) {
   const html=report([d(name,true)],locale);
   expect(html).toMatch(/nonces ou empreintes|nonces or hashes/i);
   expect(html).toMatch(/navigateurs modernes|modern browsers/i);
  }
 });
 it('does not claim a script recommendation when both more specific directives override it',()=>{
  const html=report([d('script-src',true),d('script-src-elem'),d('script-src-attr')],locale);
  expect(html).not.toMatch(/nonces ou empreintes|nonces or hashes/i);
  expect(html).toMatch(/script-src-elem/); expect(html).toMatch(/script-src-attr/);
 });
 it('uses default fallback independently when script or style directives are absent',()=>{
  const html=report([d('default-src',true),d('style-src')],locale);
  expect(html).toMatch(/script-elem, script-attr/);
  expect(html).toMatch(/style-src.*(?:prévaut|overrides)/i);
  expect(html).toMatch(/nonces ou empreintes|nonces or hashes/i);
 });
 it('uses independent element and attribute overrides',()=>{
  const html=report([d('script-src',true),d('script-src-elem')],locale);
  expect(html).toMatch(/script-src-elem.*(?:prévaut|overrides)/i);
  expect(html).toMatch(/script-src \(script-attr\)/);
  expect(html).not.toMatch(/nonces ou empreintes|nonces or hashes/i);
 });
 it('keeps wildcard advice and does not render arbitrary fields',()=>{
  const input=d('img-src',true,'domain') as Directive & {secret:string}; input.secret='SECRET_CANARY';
  const html=report([input],locale);
  expect(html).toMatch(/joker de sous-domaines|subdomain wildcard/i);
  expect(html).not.toContain('SECRET_CANARY');
 });
 it('distinguishes report-only and rejects duplicate structured directives',()=>{
  expect(report([d('script-src',true)],locale,true)).toMatch(/Report-Only.*(?:active|enforced)/i);
  const html=report([d('script-src',true),d('script-src')],locale);
  expect(html).not.toMatch(/nonces ou empreintes|nonces or hashes/i);
 });
});
