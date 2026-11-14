import {describe,it,expect} from 'vitest';
import {parseDiscoveryResponse} from './discoveryApi';
import {renderDiscoveryReport} from './discoveryReport';
import {createElement} from 'react';
import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import {vi,afterEach} from 'vitest';
import {LocaleProvider,localeKey} from './i18n';
import DiscoveryReal from './components/DiscoveryReal';

afterEach(()=>{cleanup();localStorage.clear();vi.restoreAllMocks();});
const livePage=(status:number)=>({
 ...blocked(),complete:true,reason:'none',requests:1,
 pages:[{id:'page-1',route:'page-1',depth:0,status,state:'complete',observed_at:'2026-11-12T12:00:00Z',
 observations:{http_status:status,hsts:'absent',csp:'absent',csp_report_only:'absent',csp_directives:[],csp_report_only_directives:[],csp_effective:[],csp_report_only_effective:[],cookie_prefix:{state:'none_observed',violations:null},x_content_type_options:'absent',referrer_policy:'absent',permissions_policy:'absent',cookies:{state:'none_observed',count:0,secure:null,httponly:null,samesite:null}},
 findings:[{rule_id:'hsts.header_absent.v1',qualification:'confirmed',priority:'unclassified',evidence:'absent',recommendation:'review_hsts_for_route',limit:'response_headers_only',route:'page-1',confidence:'caller_declared',provenance:'response_headers'}]}]
});

// Shape emitted by the live worker when the initial scope is blocked; no network.
const blocked=()=>({schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'scope_blocked',requests:0,bytes:0,pages:[],relations:[],resources:[],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion']});
describe('live Discovery contract',()=>{
 it('accepts a 304 without invented findings or relations',()=>{
  const page={id:'page-1',route:'/',depth:0,status:304,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null};
  const payload={...blocked(),reason:'unknown',requests:1,pages:[page]};
  expect(parseDiscoveryResponse(payload,'live').pages[0]).toEqual(page);
  expect(()=>parseDiscoveryResponse({...payload,reason:'http_refused'},'live')).toThrow();
  expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,state:'redirected'}]},'live')).toThrow();
  expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,state:'complete'}]},'live')).toThrow();
 });
 it.skipIf(!process.env.SENTINEL_304_API_PAYLOAD)('renders the actual 304 API payload in FR and EN',async()=>{
  const {readFileSync}=await import('node:fs');
  const payload=JSON.parse(readFileSync(process.env.SENTINEL_304_API_PAYLOAD!,'utf8'));
  const parsed=parseDiscoveryResponse(payload,'live');
  expect([parsed.complete,parsed.reason,parsed.requests,parsed.pages[0].status,parsed.pages[0].state]).toEqual([false,'unknown',1,304,'incomplete']);
  expect(parsed.pages[0].observations).toBeNull();expect(parsed.pages[0].findings).toEqual([]);expect(parsed.relations).toEqual([]);
  for(const language of ['fr','en'] as const){
   localStorage.setItem(localeKey,language);
   vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?{schema:'fortress.discovery-capability/1',lab:true,live:true}:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
   render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));
   fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});
   fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
   fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
   const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
   expect(html).toContain('304');expect(html).toContain(language==='fr'?'Indéterminée':'Unknown');
   expect(html).not.toMatch(/http_refused|unfavourable http response|réponse http non favorable|hsts\.header_absent|redirgée|redirigée|redirected|réponse partielle — non analysée|partial response — not analyzed/i);
   expect(screen.queryByRole('alert')).not.toBeInTheDocument();cleanup();vi.restoreAllMocks();
  }
 });
 it('accepts backend sanitized paths without conflating page identities',()=>{
  const first=livePage(200).pages[0];
  const second=livePage(204).pages[0];
  const third=livePage(200).pages[0];
  const page=(p:typeof first,id:string,route:string)=>({...p,id,route,findings:p.findings.map(f=>({...f,route}))});
  const payload={...blocked(),reason:'depth_limit',requests:3,limits:['excluded_links:2',...blocked().limits.slice(1)],pages:[page(first,'page-1','/'),page(second,'page-2','/products/{id}'),page(third,'page-3','/products/{id}')],relations:[{from:'page-1',to:'page-2',kind:'link'},{from:'page-1',to:'page-3',kind:'link'}]};
  const parsed=parseDiscoveryResponse(payload,'live');
  expect(parsed.pages.map(p=>[p.id,p.route,p.status,p.observations.http_status])).toEqual([['page-1','/',200,200],['page-2','/products/{id}',204,204],['page-3','/products/{id}',200,200]]);
  expect(parsed.pages[1].findings[0].route).toBe('/products/{id}');
  expect(parsed.relations).toEqual(payload.relations);
  expect(parsed.complete).toBe(false);
 });
 it('rejects unsafe live paths, mismatched findings and duplicate ids',()=>{
  for(const route of ['/products/<script>alert(1)</script>','/products/SECRET_TEST','/products/{id}?token=SECRET_TEST']){
   const payload=livePage(200);payload.pages[0].route=route;payload.pages[0].findings[0].route=route;
   expect(()=>parseDiscoveryResponse(payload,'live')).toThrow();
  }
  const mismatch=livePage(200);mismatch.pages[0].route='/products/{id}';
  expect(()=>parseDiscoveryResponse(mismatch,'live')).toThrow();
  const duplicate=livePage(200);duplicate.requests=2;duplicate.pages.push({...duplicate.pages[0],route:'/'});
  expect(()=>parseDiscoveryResponse(duplicate,'live')).toThrow();
 });
 it.each([200,204])('accepts an analyzed live HTTP %i page and its findings',status=>{
  const payload=livePage(status);
  const parsed=parseDiscoveryResponse(payload,'live');
  expect(parsed.pages[0].status).toBe(status);
  expect(parsed.pages[0].observations.http_status).toBe(status);
  expect(parsed.pages[0].findings).toEqual(payload.pages[0].findings);
  expect(parsed.reason).toBe('none');
 });
 it.each([200,204])('rejects a conflicting observed HTTP status for %i',status=>{
  const payload=livePage(status);
  payload.pages[0].observations.http_status=status===200?204:200;
  expect(()=>parseDiscoveryResponse(payload,'live')).toThrow();
 });
 it.each([201,202,203,205,206])('rejects unsupported analyzed HTTP %i',status=>{
  expect(()=>parseDiscoveryResponse(livePage(status),'live')).toThrow();
 });
 it.each([201,202,205,206])('accepts unsupported HTTP %i only as incomplete without security facts',status=>{
  const payload={...blocked(),reason:'unknown',requests:1,pages:[{id:'page-1',route:'/',depth:0,status,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null}]};
  expect(parseDiscoveryResponse(payload,'live').pages[0]).toEqual(payload.pages[0]);
  expect(()=>parseDiscoveryResponse({...payload,reason:'http_refused'},'live')).toThrow();
  expect(()=>parseDiscoveryResponse({...payload,complete:true,reason:'none'},'live')).toThrow();
 });
 it.each(['fr','en'] as const)('preserves HTTP 200 with incomplete body without inventing header findings (%s)',async language=>{
  const payload={...blocked(),reason:'incomplete',requests:1,pages:[{id:'page-1',route:'/',depth:0,status:200,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null}]};
  expect(parseDiscoveryResponse(payload,'live').pages[0]).toEqual(payload.pages[0]);
  expect(()=>parseDiscoveryResponse({...payload,complete:true,reason:'none'},'live')).toThrow();
  expect(()=>parseDiscoveryResponse({...payload,pages:[{...payload.pages[0],observations:{hsts:'absent'}}]},'live')).toThrow();
  localStorage.setItem(localeKey,language);
  vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?{schema:'fortress.discovery-capability/1',lab:true,live:true}:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
  render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));
  fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});
  fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
  fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
  const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
  expect(html).toContain('200');expect(html).toContain(language==='fr'?'Réponse partielle — non analysée':'Partial response — not analyzed');
  expect(html).not.toMatch(/hsts\.header_absent|<strong>Absent<\/strong>|<strong>Compliant<\/strong>|<strong>Conforme<\/strong>/i);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
 });
 it.each([[200,'byte_limit'],[200,'duration_limit'],[200,'transport_error'],[204,'incomplete'],[302,'incomplete'],[403,'incomplete'],[500,'incomplete']] as const)('preserves incomplete HTTP %i with %s and rejects fabricated observations', (status,reason)=>{
  const page={id:'page-1',route:'/',depth:0,status,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null};
  const payload={...blocked(),reason,requests:1,pages:[page]};
  expect(parseDiscoveryResponse(payload,'live').pages[0]).toEqual(page);
  expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,findings:[{rule_id:'hsts.header_absent.v1'}]}]},'live')).toThrow();
  expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,observations:{hsts:'absent'}}]},'live')).toThrow();
 });
 it.each([201,202,205,206])('renders incomplete HTTP %i without invented security facts in FR and EN',async status=>{
  for(const language of ['fr','en'] as const){
   localStorage.setItem(localeKey,language);
   const payload={...blocked(),reason:'unknown',requests:1,pages:[{id:'page-1',route:'/',depth:0,status,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null}]};
   vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?{schema:'fortress.discovery-capability/1',lab:true,live:true}:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
   render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));
   fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});
   fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
   fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
   const preview=await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i);
   const html=preview.getAttribute('srcdoc')!;
   expect(html).toContain(String(status));expect(html).toMatch(/incomplete|incomplet/i);
   expect(html).not.toMatch(/http_refused|unfavourable http response|réponse http non favorable|hsts\.header_absent/i);
   expect(screen.queryByRole('alert')).not.toBeInTheDocument();
   cleanup();vi.restoreAllMocks();
  }
 });
 it.skipIf(!process.env.SENTINEL_2XX_API_PAYLOADS)('renders actual synthetic backend API responses when integration evidence is supplied',async()=>{
  const path=process.env.SENTINEL_2XX_API_PAYLOADS!;
  const {readFileSync}=await import('node:fs');
  const payloads=JSON.parse(readFileSync(path,'utf8'));
  expect(payloads.map((x:any)=>x.pages[0].status)).toEqual([201,202,205,206]);
  for(const payload of payloads) for(const language of ['fr','en'] as const){
   const parsed=parseDiscoveryResponse(payload,'live');
   expect(parsed.complete).toBe(false);expect(parsed.reason).toBe('unknown');
   expect(parsed.pages[0].observations).toBeNull();expect(parsed.pages[0].findings).toEqual([]);
   localStorage.setItem(localeKey,language);
   vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?{schema:'fortress.discovery-capability/1',lab:true,live:true}:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
   render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));
   fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});
   fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
   fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
   const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
   expect(html).toContain(String(parsed.pages[0].status));expect(html).toMatch(/incomplete|incomplet/i);
   expect(html).not.toMatch(/http_refused|unfavourable http response|réponse http non favorable|hsts\.header_absent/i);
   cleanup();vi.restoreAllMocks();
  }
 });
 it.each(['en','fr'] as const)('renders partial live HTTP evidence and sanitized paths in %s',async language=>{
  localStorage.setItem(localeKey,language);
  const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async u=>{
   const url=String(u);
   if(url.endsWith('/discovery/capability'))return new Response(JSON.stringify({schema:'fortress.discovery-capability/1',lab:true,live:true}));
   if(url.endsWith('/mvp/capability'))return new Response(JSON.stringify({capability:'a'.repeat(32)}));
   if(url.endsWith('/discovery/live')){const payload=livePage(204);payload.complete=false;payload.reason='depth_limit';payload.requests=3;payload.limits[0]='excluded_links:2';const item=payload.pages[0];payload.pages=[{...item,route:'/',findings:item.findings.map(f=>({...f,route:'/'}))},{...item,id:'page-2',route:'/products/{id}',findings:item.findings.map(f=>({...f,route:'/products/{id}'}))},{...item,id:'page-3',route:'/products/{id}',findings:item.findings.map(f=>({...f,route:'/products/{id}'}))}];return new Response(JSON.stringify(payload));}
   throw new Error('Unexpected fetch');
  });
  render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));
  fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});
  fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));
  await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
  fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));
  fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
  const preview=await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i);
  const html=preview.getAttribute('srcdoc')!;
  expect(html).toContain('204');
  expect(html).toContain('page-1 — /');
  expect(html).toContain('page-2 — /products/{id}');
  expect(html).toContain('page-3 — /products/{id}');
  expect(html).toContain(language==='fr'?'Liens exclus : 2':'Excluded links: 2');
  expect(html).toMatch(/partial|incomplete|partiel|incomplet/i);
  expect(html).toContain(language==='fr'?'Les chemins assainis sont des projections, pas des chemins exacts.':'Sanitized paths are projections, not exact paths.');
  expect(html).not.toMatch(/http_refused|Unfavourable HTTP response/i);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(fetcher.mock.calls.some(([u])=>String(u).endsWith('/discovery/live'))).toBe(true);
 });
 it.each(['fr','en'] as const)('attributes different findings and links with colliding structural paths in preview and export (%s)',async language=>{
  localStorage.setItem(localeKey,language);
  const first=livePage(200).pages[0], route='/{segment}/{segment}';
  const page1={...first,route,findings:first.findings.map(f=>({...f,route}))};
  const page2={...first,id:'page-2',route,observations:{...first.observations,hsts:'disabled'},findings:first.findings.map(f=>({...f,route,rule_id:'hsts.disabled.v1',evidence:'disabled'}))};
  const payload={...blocked(),complete:true,reason:'none',requests:2,pages:[page1,page2],relations:[{from:'page-1',to:'page-2',kind:'link'}],resources:[{page:'page-2',kind:'script',count:2}]};
  let blob:Blob|undefined;
  const create=URL.createObjectURL,revoke=URL.revokeObjectURL;
  URL.createObjectURL=vi.fn(v=>{blob=v as Blob;return 'blob:test';});URL.revokeObjectURL=vi.fn();vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
  vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?{schema:'fortress.discovery-capability/1',lab:true,live:true}:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
  try {
   render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));
   fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});
   fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
   fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
   const iframe=await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i);expect(iframe).toHaveAttribute('sandbox','');
   const html=iframe.getAttribute('srcdoc')!;
   const doc=new DOMParser().parseFromString(html,'text/html');
   const cards=[...doc.querySelectorAll('article')];
   const security1=cards.find(c=>c.querySelector('h3')?.textContent===`page-1 — ${route}` && c.textContent?.includes('hsts.header_absent.v1'));
   const security2=cards.find(c=>c.querySelector('h3')?.textContent===`page-2 — ${route}` && c.textContent?.includes('hsts.disabled.v1'));
   expect(security1).toBeDefined();expect(security1?.textContent).not.toContain('hsts.disabled.v1');
   expect(security2).toBeDefined();expect(security2?.textContent).not.toContain('hsts.header_absent.v1');
   expect(html).toContain(`page-1 — ${route} → page-2 — ${route}`);expect(html).toContain(`page-2 — ${route} · Script: 2`);
   expect(html).toContain(language==='fr'?'Les identifiants page-N sont des alias':'Page-N identifiers are aliases');
   expect(html).toContain(language==='fr'?'pas des chemins exacts':'not exact paths');expect(html).not.toMatch(/SECRET_TEST|<script/i);
   fireEvent.click(screen.getByRole('button',{name:/download discovery report|télécharger le rapport discovery/i}));
   const output=await new Promise<string>((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result));r.onerror=()=>reject(r.error);r.readAsText(blob!);});expect(output).toBe(html);
  } finally {URL.createObjectURL=create;URL.revokeObjectURL=revoke;}
 });
 it('accepts the scope-blocked backend response without presenting it as complete',()=>{
  expect(parseDiscoveryResponse(blocked(),'live').reason).toBe('scope_blocked');
 });
 it('rejects incompatible live limits and impossible counts',()=>{
  for(const changes of [{limits:[]},{limits:['lab_only',...blocked().limits]},{requests:31},{bytes:10485761},{pages:[{id:'page-1'}]}]){
   expect(()=>parseDiscoveryResponse({...blocked(),...changes},'live')).toThrow();
  }
 });
 it.each(['fr','en'] as const)('renders scope-blocked reason in %s',language=>{
  const html=renderDiscoveryReport({provenance:'declared_observation',completeness:'incomplete',limits:['scope'],pages:[],relations:[],resources:[],crawl:{pages:0,requests:0,bytes:0,complete:false,reason:'scope_blocked'}},language);
  expect(html).toContain(language==='fr'?'Périmètre bloqué':'Scope blocked');
 });
});

 it.each(['budget','timeout'] as const)('accepts duration-limited partial headers only with a consistent diagnostic (%s)',phase=>{
  const page={id:'page-1',route:'/',depth:0,status:200,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null,partial_headers:{present:['content-security-policy','set-cookie'],completeness:'headers_validated_body_incomplete'}};
  const payload={...blocked(),reason:'duration_limit',requests:1,bytes:10,pages:[page],diagnostic:{phase,requests_sent:1,responses_received:1}};
  expect(parseDiscoveryResponse(payload,'live')).toEqual(payload);
  expect(()=>parseDiscoveryResponse({...payload,complete:true},'live')).toThrow();
  expect(()=>parseDiscoveryResponse({...payload,diagnostic:{...payload.diagnostic,phase:'http'}},'live')).toThrow();
  expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,findings:[{rule_id:'hsts.header_absent.v1'}]}]},'live')).toThrow();
 });
 it.each([['fr','budget'],['fr','timeout'],['en','budget'],['en','timeout']] as const)('renders deadline partial HTTP evidence without an audit (%s, %s)',async (language,phase)=>{
  const page={id:'page-1',route:'/',depth:0,status:200,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null,partial_headers:{present:['content-security-policy','set-cookie'],completeness:'headers_validated_body_incomplete'}};
  const payload={...blocked(),reason:'duration_limit',requests:1,bytes:10,pages:[page],diagnostic:{phase,requests_sent:1,responses_received:1}};
  localStorage.setItem(localeKey,language);
  vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?{schema:'fortress.discovery-capability/1',lab:true,live:true}:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
  render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));
  fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});
  fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
  fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
  const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
  expect(html).toContain('200');expect(html).toContain('content-security-policy');expect(html).toContain('set-cookie');
  expect(html).toContain(language==='fr'?'Corps incomplet':'Body incomplete');
  expect(html).toContain(language==='fr'?'Limite de durée atteinte':'Duration limit reached');
  expect(html).toContain(language==='fr'?`Phase : ${phase==='budget'?'Budget':'Délai dépassé'}`:`Phase: ${phase==='budget'?'Budget':'Timeout'}`);
  expect(html).toContain(language==='fr'?'Réponse partielle — non analysée':'Partial response — not analyzed');
  expect(html).not.toMatch(/hsts\.header_absent|<strong>Absent<\/strong>|<strong>Compliant<\/strong>|<strong>Conforme<\/strong>/i);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
 });
 it('validates partial header presence strictly',()=>{
  const page={id:'page-1',route:'/',depth:0,status:403,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null,partial_headers:{present:['set-cookie','content-security-policy'],completeness:'headers_validated_body_incomplete'}};
  const payload={...blocked(),reason:'incomplete',requests:1,pages:[page]};
  expect(parseDiscoveryResponse(payload,'live').pages[0]).toEqual(page);
  for(const partial_headers of [{...page.partial_headers,present:[]},{...page.partial_headers,present:['set-cookie','set-cookie']},{...page.partial_headers,present:['SECRET_TEST']},{...page.partial_headers,value:'SECRET_TEST'},{...page.partial_headers,completeness:'complete'}]) {
   if(partial_headers.present.length===0) expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,partial_headers}]},'live')).not.toThrow();
   else expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,partial_headers}]},'live')).toThrow();
  }
  expect(()=>parseDiscoveryResponse({...payload,pages:[{...page,state:'access_denied'}]},'live')).toThrow();
 });
 it.each(['fr','en'] as const)('shows validated partial headers in preview and downloaded report (%s)',async language=>{
  const page={id:'page-1',route:'/',depth:0,status:403,state:'incomplete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null,partial_headers:{present:['set-cookie','content-security-policy'],completeness:'headers_validated_body_incomplete'}};
  const payload={...blocked(),reason:'incomplete',requests:1,pages:[page]}; localStorage.setItem(localeKey,language);let blob:Blob|undefined;
  const create=URL.createObjectURL,revoke=URL.revokeObjectURL; URL.createObjectURL=vi.fn(v=>{blob=v as Blob;return 'blob:test';});URL.revokeObjectURL=vi.fn();vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
  vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?{schema:'fortress.discovery-capability/1',lab:true,live:true}:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
  try{render(createElement(LocaleProvider,null,createElement(DiscoveryReal)));fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
   const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;expect(html).toContain('set-cookie');expect(html).toContain('content-security-policy');expect(html).toContain(language==='fr'?'Corps incomplet':'Body incomplete');expect(html).not.toMatch(/SECRET_TEST|hsts\.header_absent|<strong>Conforme<\/strong>|<strong>Compliant<\/strong>/i);
   fireEvent.click(screen.getByRole('button',{name:/download discovery report|télécharger le rapport discovery/i}));const output=await new Promise<string>((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result));r.onerror=()=>reject(r.error);r.readAsText(blob!);});expect(output).toBe(html);
  }finally{URL.createObjectURL=create;URL.revokeObjectURL=revoke;}
 });
