import {it,expect,vi,afterEach} from 'vitest';
import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import {LocaleProvider,localeKey} from './i18n';
import DiscoveryReal from './components/DiscoveryReal';
import {parseDiscoveryResponse} from './discoveryApi';

afterEach(()=>{cleanup();localStorage.clear();vi.restoreAllMocks();});
const payload=()=>({schema:'fortress.discovery/1',provenance:'lab',complete:false,reason:'http_refused',requests:2,bytes:10,pages:[{id:'page-1',route:'/products/{id}',depth:0,status:403,state:'access_denied',observed_at:null,findings:[],observations:null},{id:'page-2',route:'page-2',depth:1,status:302,state:'redirected',observed_at:null,findings:[],observations:null}],relations:[],resources:[],limits:['excluded_links:2']});
it.each(['fr','en'] as const)('reports responses separately from analyzed pages and identifies provided paths (%s)',async locale=>{
 localStorage.setItem(localeKey,locale);
 vi.spyOn(globalThis,'fetch').mockImplementation(async u=>String(u).endsWith('capability')?new Response(JSON.stringify({capability:'a'.repeat(32)})):new Response(JSON.stringify(payload())));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 fireEvent.click(screen.getByLabelText(/authorize the discovery laboratory|autorise le laboratoire discovery/i));fireEvent.click(screen.getByRole('button',{name:/run discovery lab|lancer le laboratoire discovery/i}));
 const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
 expect(html).toContain(locale==='fr'?'Réponses HTTP représentées : 2':'HTTP responses represented: 2');
 expect(html).toContain(locale==='fr'?'Pages analysées : 0':'Pages analyzed: 0');
 expect(html).toContain('/products/{id}');expect(html).toContain('page-2');
 expect(html).toContain(locale==='fr'?'Liens exclus : 2':'Excluded links: 2');
 expect(html).toContain(locale==='fr'?'motifs non fournis':'reasons not provided');
 expect(screen.getByText(locale==='fr'?'Réponses HTTP représentées : 2 · Pages analysées : 0':'HTTP responses represented: 2 · Pages analyzed: 0')).toBeInTheDocument();
 expect(screen.getByText(locale==='fr'?'Liens exclus : 2 ; motifs non fournis.':'Excluded links: 2; reasons not provided.')).toBeInTheDocument();
});
it('rejects arbitrary route content, secret and XSS',()=>{for(const route of ['/secret-TOKEN','/products/<script>','/products?token=SECRET','https://example.org/x']){const x=payload();x.pages[0].route=route;expect(()=>parseDiscoveryResponse(x,'lab')).toThrow();}});
it.each(['fr','en'] as const)('keeps live mode closed without a supported capability and names scope exclusions (%s)',locale=>{
 localStorage.setItem(localeKey,locale);const f=vi.spyOn(globalThis,'fetch');render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 expect(screen.getByText(locale==='fr'?/paramètres et authentification sont exclus/i:/query parameters and authentication are excluded/i)).toBeInTheDocument();
 fireEvent.change(screen.getByLabelText(/Discovery HTTPS origin|Origine HTTPS Discovery/i),{target:{value:'https://example.org'}});
 fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));
 expect(screen.getByRole('button',{name:/Start Discovery|Démarrer Discovery/i})).toBeDisabled();expect(f).not.toHaveBeenCalled();
});

it.each(['fr','en'] as const)('incomplete zero-page diagnostic is honest in cockpit and preview (%s)',async locale=>{
 localStorage.setItem(localeKey,locale);
 const data={...payload(),reason:'transport_error',requests:1,bytes:0,pages:[],relations:[],resources:[],limits:['excluded_links:0'],diagnostic:{phase:'tls',requests_sent:null,responses_received:null}};
 vi.spyOn(globalThis,'fetch').mockImplementation(async u=>String(u).endsWith('capability')?new Response(JSON.stringify({capability:'a'.repeat(32)})):new Response(JSON.stringify(data)));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 fireEvent.click(screen.getByLabelText(/authorize the discovery laboratory|autorise le laboratoire discovery/i));fireEvent.click(screen.getByRole('button',{name:/run discovery lab|lancer le laboratoire discovery/i}));
 const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
 for(const text of locale==='fr'?['Diagnostic incomplet : aucune page observée','Tentatives : 1','Requêtes transmises : inconnues','Réponses reçues : inconnues','Phase : TLS']:['Incomplete diagnostic: no page observed','Attempts: 1','Requests sent: unknown','Responses received: unknown','Phase: TLS']) {expect(html).toContain(text);expect(screen.getByText((_,element)=>element?.tagName==='P'&&element.textContent?.includes(text)===true)).toBeInTheDocument();}
 expect(html).not.toMatch(/Limites: Aucune|Limitations: None|Liens exclus : 0|Excluded links: 0/i);
});

it.each(['fr','en'] as const)('exports exactly the preview with known diagnostic counts for partial responses (%s)',async locale=>{
 localStorage.setItem(localeKey,locale);
 const data={...payload(),pages:payload().pages.slice(0,1),diagnostic:{phase:'http',requests_sent:2,responses_received:1}};
 vi.spyOn(globalThis,'fetch').mockImplementation(async u=>String(u).endsWith('capability')?new Response(JSON.stringify({capability:'a'.repeat(32)})):new Response(JSON.stringify(data)));
 let blob:Blob|undefined;const oldCreate=URL.createObjectURL,oldRevoke=URL.revokeObjectURL;
 URL.createObjectURL=vi.fn(value=>{blob=value as Blob;return 'blob:test';});URL.revokeObjectURL=vi.fn();vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
 try {
  render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);fireEvent.click(screen.getByLabelText(/authorize the discovery laboratory|autorise le laboratoire discovery/i));fireEvent.click(screen.getByRole('button',{name:/run discovery lab|lancer le laboratoire discovery/i}));
  const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
  expect(html).toContain(locale==='fr'?'Requêtes transmises : 2':'Requests sent: 2');expect(html).toContain(locale==='fr'?'Réponses reçues : 1':'Responses received: 1');
  fireEvent.click(screen.getByRole('button',{name:/download discovery report|télécharger le rapport discovery/i}));expect(blob).toBeDefined();
  const exported=await new Promise<string>((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result as string);reader.onerror=reject;reader.readAsText(blob!);});expect(exported).toBe(html);
 } finally {URL.createObjectURL=oldCreate;URL.revokeObjectURL=oldRevoke;}
});
it.each(['fr','en'] as const)('historical zero-page response remains unknown (%s)',async locale=>{
 localStorage.setItem(localeKey,locale);const data={...payload(),pages:[],relations:[],resources:[],limits:['excluded_links:0']};
 vi.spyOn(globalThis,'fetch').mockImplementation(async u=>String(u).endsWith('capability')?new Response(JSON.stringify({capability:'a'.repeat(32)})):new Response(JSON.stringify(data)));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);fireEvent.click(screen.getByLabelText(/authorize the discovery laboratory|autorise le laboratoire discovery/i));fireEvent.click(screen.getByRole('button',{name:/run discovery lab|lancer le laboratoire discovery/i}));
 const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;expect(html).toContain(locale==='fr'?'Requêtes transmises : inconnues':'Requests sent: unknown');expect(html).toContain(locale==='fr'?'Phase : inconnue':'Phase: unknown');
});

it.each(['fr','en'] as const)('reports a completed observation without downgrading it (%s)',async locale=>{
 localStorage.setItem(localeKey,locale);
 const observations={http_status:200,hsts:'positive',csp:'absent',csp_report_only:'absent',csp_directives:[],csp_report_only_directives:[],csp_effective:[],csp_report_only_effective:[],cookie_prefix:{state:'none_observed',violations:null},x_content_type_options:'present',referrer_policy:'absent',permissions_policy:'absent',cookies:{state:'none_observed',count:0,secure:null,httponly:null,samesite:null}};
 const data={...payload(),complete:true,reason:'none',requests:1,pages:[{id:'page-1',route:'page-1',depth:0,status:200,state:'complete',observed_at:'2026-11-12T12:00:00Z',findings:[],observations}],diagnostic:{phase:'none',requests_sent:1,responses_received:1}};
 vi.spyOn(globalThis,'fetch').mockImplementation(async u=>String(u).endsWith('capability')?new Response(JSON.stringify({capability:'a'.repeat(32)})):new Response(JSON.stringify(data)));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);fireEvent.click(screen.getByLabelText(/authorize the discovery laboratory|autorise le laboratoire discovery/i));fireEvent.click(screen.getByRole('button',{name:/run discovery lab|lancer le laboratoire discovery/i}));
 const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;expect(html).toContain(locale==='fr'?'Pages analysées : 1':'Pages analyzed: 1');expect(html).toContain(locale==='fr'?'Réponses reçues : 1':'Responses received: 1');expect(html).not.toContain(locale==='fr'?'Diagnostic incomplet : aucune page observée':'Incomplete diagnostic: no page observed');
});
