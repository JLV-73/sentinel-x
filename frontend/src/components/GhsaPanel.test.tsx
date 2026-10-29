import {render,screen,fireEvent,waitFor,within,act} from '@testing-library/react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import official from './fixtures/ghsa-official-log4shell.json';
import App from '../App';
import GhsaPanel from './GhsaPanel';
import {LocaleProvider} from '../i18n';
import type {GhsaResult,GhsaAttempt,GhsaProvenance,GhsaAdvisory} from '../types';
import {defaultResponse,json,vuln,record} from '../test/fixtures';
vi.mock('../components/Charts',()=>({TrendChart:()=> <div/>,VendorChart:()=> <div/>}));
// Offline, synthetic contract fixture; NOT a collected/sample GitHub advisory.
const empty:GhsaResult['ghsa']={state:'not_requested',stale:false,retained_after_error:false,collected_at:null,source_date:null,data:null,provenance:null,last_attempt:null,last_success:null};
const control:GhsaResult['control']={next_request_at:null,freshness_hours:24,minimum_interval_seconds:65,max_advisories:100,attribution:{name:'GitHub Advisory Database',url:'https://github.com/advisories',license:'CC-BY-4.0',license_url:'https://creativecommons.org/licenses/by/4.0/'}};
const initial:GhsaResult={cve_id:vuln.cveID,ghsa:empty,control};
const provenance:GhsaProvenance={source:'ghsa',url:'https://api.github.com/advisories?cve_id=CVE-2026-1234&type=reviewed&per_page=100',sha256:'d'.repeat(64),collected_at:'2026-10-28T12:00:00Z',raw_file:'intelligence_raw/ghsa/test-only.json'};
const attempt:GhsaAttempt={id:31,source:'ghsa',status:'success',started_at:'2026-10-28T12:00:00Z',finished_at:'2026-10-28T12:00:01Z',requested:1,available:0,absent:1,failed:0,error:null,provenances:[provenance]};
const absent:GhsaResult={...initial,ghsa:{...empty,state:'absent',provenance,collected_at:provenance.collected_at,last_attempt:attempt,last_success:attempt}};
const advisory:GhsaAdvisory={ghsa_id:'GHSA-test-only-0001',cve_id:vuln.cveID,type:'reviewed',html_url:'https://github.com/advisories/GHSA-test-only-0001',summary:'Test-only advisory <img src=x onerror=alert(1)>',description:'# Original test-only description\n<script>alert(1)</script>',severity:'critical',cvss:{vector_string:'CVSS:3.1/AV:N/AC:L',score:10},cvss_severities:{cvss_v3:{vector_string:'CVSS:3.1/AV:N/AC:L',score:10},cvss_v4:{vector_string:null,score:0}},identifiers:[{type:'CVE',value:vuln.cveID},{type:'GHSA',value:'GHSA-test-only-0001'}],published_at:'2026-10-20T10:11:12Z',updated_at:'2026-10-26T09:08:07Z',github_reviewed_at:'2026-10-21T01:02:03Z',nvd_published_at:null,withdrawn_at:null,vulnerabilities:Array.from({length:10},(_,i)=>({package:{ecosystem:'Maven',name:`test-only:package-${i}`},vulnerable_version_range:`>= 1.${i}, < 2.${i}`,first_patched_version:i===0?null:`2.${i}`}))};
const withdrawn:GhsaAdvisory={...advisory,ghsa_id:'GHSA-test-only-0002',html_url:'javascript:alert(1)',summary:'Withdrawn test-only advisory',withdrawn_at:'2026-10-27T04:05:06Z',vulnerabilities:[],cvss:null,cvss_severities:null};
const available:GhsaResult={...absent,ghsa:{...absent.ghsa,state:'available',source_date:advisory.updated_at,data:{date:advisory.updated_at,advisories:[advisory,withdrawn]},last_attempt:{...attempt,available:1,absent:0},last_success:{...attempt,available:1,absent:0}}};
let current=structuredClone(initial);
const endpoint=`/api/intelligence/ghsa/${vuln.cveID}`;
beforeEach(()=>{window.location.hash=`cve/${vuln.cveID}`;current=structuredClone(initial);vi.stubGlobal('fetch',vi.fn(async(url:string)=>url===endpoint?json(current):defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it.each([['fr','Non renseigné'],['en','Not specified']] as const)('preserves a provided range and labels a null range in %s without changing source JSON',async(locale,label)=>{
 current=structuredClone(available);
 const original=current.ghsa.data!.advisories[0];
 original.vulnerabilities=original.vulnerabilities.slice(0,2);
 original.vulnerabilities[1].vulnerable_version_range=null;
 const expected=structuredClone(original);
 render(<App/>);
 const entries=await screen.findAllByTestId('ghsa-package');
 fireEvent.click(screen.getByTestId(`language-${locale}`));
 expect(within(entries[0]).getByText('>= 1.0, < 2.0')).toHaveAttribute('lang','en');
 expect(within(entries[1]).getByText(label)).toBeVisible();
 const source=screen.getAllByTestId('ghsa-advisory')[0];
 const raw=Array.from(source.querySelectorAll('details pre')).map(node=>JSON.parse(node.textContent!)).find(value=>value.ghsa_id===expected.ghsa_id);
 expect(raw).toEqual(expected);
 expect(raw.vulnerabilities[1].vulnerable_version_range).toBeNull();
});
it('preserves multiple original records, ten package ranges, withdrawal, missing fixes and source placeholders without HTML',async()=>{
 current=structuredClone(available);render(<App/>);
 const panel=await screen.findByTestId('ghsa-panel');
 expect(await within(panel).findByText(advisory.summary)).toHaveAttribute('lang','en');
 expect(within(panel).getAllByText((_,node)=>node?.tagName==='P'&&node.textContent===advisory.description)[0]).toHaveAttribute('lang','en');
 expect(within(panel).getAllByTestId('ghsa-advisory')).toHaveLength(2);
 expect(within(panel).getAllByTestId('ghsa-package')).toHaveLength(10);
 for(const entry of advisory.vulnerabilities){expect(within(panel).getByText(entry.package.name)).toBeVisible();expect(within(panel).getByText(entry.vulnerable_version_range!)).toHaveAttribute('lang','en');}
 expect(within(panel).getByText('Version corrigée non renseignée — pas de recommandation déduite.')).toBeVisible();
 expect(within(panel).getByText('Avis retiré par la source')).toBeVisible();
 expect(within(panel).getByText('2026-10-27T04:05:06Z')).toBeVisible();
 expect(within(panel).getAllByText('2026-10-20T10:11:12Z').length).toBeGreaterThan(0);
 expect(within(panel).getAllByTestId('ghsa-cvss')).toHaveLength(2);
 expect(within(panel).getByText(/cvss_v4.*Vecteur non renseigné/)).toBeVisible();
 expect(panel.querySelector('img,script')).toBeNull();expect(panel.querySelector('a[href^="javascript:"]')).toBeNull();
 expect(within(panel).getByRole('link',{name:'GitHub Advisory Database'})).toHaveAttribute('href',control.attribution.url);
 expect(within(panel).getByRole('link',{name:'CC-BY-4.0'})).toHaveAttribute('href',control.attribution.license_url);
 expect(within(panel).getByText(/Cache local et projection des champs/)).toBeVisible();
 const raw=within(panel).getAllByText('Avis GHSA · JSON original')[0].closest('details')!;
 expect(JSON.parse(raw.querySelector('pre')!.textContent!)).toEqual(advisory);
 expect(within(panel).getAllByText(provenance.sha256).length).toBeGreaterThan(0);
 fireEvent.click(screen.getByTestId('language-en'));
 expect(within(panel).getByText('Withdrawn by the source')).toBeVisible();
 expect(within(panel).getByText(advisory.summary)).toHaveAttribute('lang','en');
 expect(within(panel).getByText('Patched version not specified — no recommendation inferred.')).toBeVisible();
});
it.each([
 ['absent','Aucun avis GitHub examiné renvoyé pour cette CVE. Cela ne démontre pas l’absence de vulnérabilité.'],
 ['unavailable','Recherche GHSA indisponible. Aucun nouvel avis ni correctif déduit.'],
 ['stale','Instantané GHSA ancien — vérifier les dates de la source.'],
] as const)('distinguishes GHSA %s from an unrequested search',async(state,label)=>{
 current={...absent,ghsa:{...absent.ghsa,state,stale:state==='stale'}};render(<App/>);
 const panel=await screen.findByTestId('ghsa-panel');
 expect(await within(panel).findByText(label)).toBeVisible();
 expect(within(panel).getByTestId('ghsa-state')).toHaveAttribute('data-state',state);
 expect(within(panel).queryByTestId('ghsa-advisory')).not.toBeInTheDocument();
});
it('displays the source cooldown and retained cached records after a structured failed refresh',async()=>{
 let posted=false;
 const retained:GhsaResult={...available,ghsa:{...available.ghsa,retained_after_error:true,last_attempt:{...attempt,id:32,status:'failed',error:'test-only GitHub rate limit'}},control:{...control,next_request_at:'2099-10-28T12:01:05Z'}};
 vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(init?.method==='POST'){posted=true;return json({detail:{error:'test-only rate limit',attempt:retained.ghsa.last_attempt,cached:retained}},502);}
  return url===endpoint?json(posted?retained:available):defaultResponse(url);
 }));render(<App/>);const panel=await screen.findByTestId('ghsa-panel');
 fireEvent.click(await within(panel).findByRole('button',{name:'Actualiser GHSA pour cette CVE'}));
 expect(await within(panel).findByText(/Dernières valeurs validées conservées après erreur/)).toBeVisible();
 expect(within(panel).getByText(advisory.summary)).toBeVisible();
 expect(within(panel).getByText('2099-10-28T12:01:05Z')).toBeVisible();
 expect(within(panel).getByText(/Intervalle minimal.*65.*24.*100/)).toBeVisible();
 expect(within(panel).getByText(/test-only rate limit/, {selector:'pre'})).toBeInTheDocument();
 expect(within(panel).queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
 expect(fetch).toHaveBeenCalledWith(`${endpoint}?refresh=true`,expect.objectContaining({method:'POST'}));
 fireEvent.click(screen.getByTestId('language-en'));
 expect(within(panel).getByText(/retained after an error/)).toBeVisible();
});
it('offers a local-only retry after GET fails',async()=>{
 let reads=0;vi.stubGlobal('fetch',vi.fn(async(url:string)=>url===endpoint?(++reads===1?json({detail:{error:'test-only database failure'}},503):json(initial)):defaultResponse(url)));
 render(<App/>);const panel=await screen.findByTestId('ghsa-panel');
 fireEvent.click(await within(panel).findByRole('button',{name:'Relire le cache local GHSA'}));
 expect(await within(panel).findByText('Aucune recherche GHSA enregistrée pour cette CVE.')).toBeVisible();
 expect(vi.mocked(fetch).mock.calls.every(([,init])=>init?.method!=='POST')).toBe(true);
});
it.each(['attempt','hash','state','missingHash','retained'] as const)('never confirms a mismatched %s readback',async(change)=>{
 let posted=false;const different=structuredClone(absent);
 if(change==='attempt')different.ghsa.last_attempt!.id++;
 if(change==='hash')different.ghsa.provenance!.sha256='e'.repeat(64);
 if(change==='state')different.ghsa.state='unavailable';
 if(change==='missingHash')different.ghsa.provenance=null;
 if(change==='retained')different.ghsa.retained_after_error=true;
 vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(init?.method==='POST'){posted=true;return json(absent);}
  return url===endpoint?json(posted?different:initial):defaultResponse(url);
 }));render(<App/>);const panel=await screen.findByTestId('ghsa-panel');
 fireEvent.click(await within(panel).findByRole('button',{name:'Rechercher GHSA pour cette CVE'}));
 expect(await within(panel).findByText(/Impossible de confirmer ce résultat par relecture locale/)).toBeVisible();
 expect(within(panel).queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
});
it('retains cached values when both POST and local readback fail, without unverified success',async()=>{
 let posted=false;vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(init?.method==='POST'){posted=true;return json({detail:'test-only timeout'},502);}
  if(url===endpoint){if(posted)throw new TypeError('test-only local offline');return json(available);}return defaultResponse(url);
 }));render(<App/>);const panel=await screen.findByTestId('ghsa-panel');
 fireEvent.click(await within(panel).findByRole('button',{name:'Actualiser GHSA pour cette CVE'}));
 expect(await within(panel).findByText(/Impossible de confirmer ce résultat par relecture locale/)).toBeVisible();
 expect(within(panel).getByText(advisory.summary)).toBeVisible();
 expect(within(panel).queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
});
it('aborts the old CVE action and rejects late POST results after a CVE change',async()=>{
 let release:(r:Response)=>void=()=>{};let postSignal:AbortSignal|undefined;
 const second='CVE-2026-9999';
 vi.stubGlobal('fetch',vi.fn((url:string,init?:RequestInit)=>{
  if(init?.method==='POST'){postSignal=init.signal as AbortSignal;return new Promise<Response>(resolve=>{release=resolve;});}
  return Promise.resolve(url===endpoint?json(available):json({...initial,cve_id:second}));
 }));
 const ui=render(<LocaleProvider><GhsaPanel cveId={vuln.cveID}/></LocaleProvider>);
 fireEvent.click(await screen.findByRole('button',{name:'Actualiser GHSA pour cette CVE'}));
 ui.rerender(<LocaleProvider><GhsaPanel cveId={second}/></LocaleProvider>);
 expect(postSignal?.aborted).toBe(true);
 expect(await screen.findByText('Aucune recherche GHSA enregistrée pour cette CVE.')).toBeVisible();
 await act(async()=>{release(json(available));});
 expect(screen.queryByText(advisory.summary)).not.toBeInTheDocument();
 expect(screen.queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
 expect(vi.mocked(fetch).mock.calls.filter(([url])=>url===endpoint)).toHaveLength(1);
});
it('keeps GHSA out of overview, catalogue and triage navigation',async()=>{
 window.location.hash='overview';render(<App/>);await screen.findByTestId('metric-total');
 expect(screen.queryByTestId('ghsa-panel')).not.toBeInTheDocument();
 for(const route of ['intelligence','triage']){await act(async()=>{window.location.hash=route;fireEvent(window,new HashChangeEvent('hashchange'));});expect(screen.queryByTestId('ghsa-panel')).not.toBeInTheDocument();}
 expect(vi.mocked(fetch).mock.calls.every(([url,init])=>!String(url).includes('/ghsa/')&&init?.method!=='POST')).toBe(true);
});
it('renders the full offline official Log4Shell JSON: ten ranges, five names, string fixes, no promoted embedded EPSS',async()=>{
 // Real official JSON supplied by the parent; synthetic local API wrapper only.
 // GitHub Advisory Database, CC-BY-4.0. Original advisory preserved byte-for-byte in fixture.
 const original=official as GhsaAdvisory[];
 const real=original[0];const result:GhsaResult={...available,cve_id:real.cve_id!,ghsa:{...available.ghsa,data:{date:real.updated_at,advisories:original}}};
 vi.stubGlobal('fetch',vi.fn(async()=>json(result)));
 render(<LocaleProvider><GhsaPanel cveId={real.cve_id!}/></LocaleProvider>);
 expect(await screen.findByText(real.summary)).toBeVisible();
 expect(screen.getAllByTestId('ghsa-advisory')).toHaveLength(1);
 expect(screen.getAllByTestId('ghsa-package')).toHaveLength(10);
 expect(new Set(real.vulnerabilities.map(v=>v.package.name)).size).toBe(5);
 expect(screen.getAllByText('2.15.0').length).toBeGreaterThan(0);
 expect(screen.queryByTestId('epss-score')).not.toBeInTheDocument();
 const disclosure=screen.getByText('Avis GHSA · JSON original').closest('details')!;
 expect(JSON.parse(disclosure.querySelector('pre')!.textContent!)).toEqual(real);
 expect(screen.getAllByTestId('ghsa-cvss')).toHaveLength(2);
 expect(screen.getByText(/cvss_v4.*Vecteur non renseigné/)).toBeVisible();
 expect(screen.queryByText(/Dix|10 paquets distincts/)).not.toBeInTheDocument();
});
it('collects once only on explicit action and confirms the exact local readback',async()=>{
 let release:(r:Response)=>void=()=>{};let posted=false;
 vi.stubGlobal('fetch',vi.fn((url:string,init?:RequestInit)=>{
  if(init?.method==='POST'){posted=true;return new Promise<Response>(resolve=>{release=resolve;});}
  return Promise.resolve(url===endpoint?json(posted?absent:initial):defaultResponse(url));
 }));render(<App/>);
 const button=await screen.findByRole('button',{name:'Rechercher GHSA pour cette CVE'});
 await waitFor(()=>expect(button).toBeEnabled());fireEvent.click(button);fireEvent.click(button);
 expect(button).toBeDisabled();expect(screen.queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
 await act(async()=>{release(json(absent));});
 expect(await within(screen.getByTestId('ghsa-panel')).findByText('Résultat de la source vérifié par relecture locale.')).toBeVisible();
 const posts=vi.mocked(fetch).mock.calls.filter(([,init])=>init?.method==='POST');
 expect(posts).toHaveLength(1);expect(posts[0][0]).toBe(`${endpoint}?refresh=false`);
 expect(posts[0][1]).toMatchObject({cache:'no-store',headers:{'X-Sentinel-Request':'sync'},signal:expect.any(AbortSignal)});
 expect(posts[0][1]?.body).toBeUndefined();
 expect(vi.mocked(fetch).mock.calls.filter(([url])=>url===endpoint)).toHaveLength(2);
});
it('adds only a wide detail panel with a local GET; switching language never collects',async()=>{
 render(<App/>);
 const panel=await screen.findByTestId('ghsa-panel');
 expect(panel.closest('.detail-main')).not.toBeNull();
 expect(await within(panel).findByText('Aucune recherche GHSA enregistrée pour cette CVE.')).toBeVisible();
 expect(fetch).toHaveBeenCalledWith(endpoint,expect.objectContaining({cache:'no-store',signal:expect.any(AbortSignal)}));
 const count=vi.mocked(fetch).mock.calls.length;
 fireEvent.click(screen.getByTestId('language-en'));
 expect(within(panel).getByText('No GHSA search recorded for this CVE.')).toBeVisible();
 expect(vi.mocked(fetch).mock.calls).toHaveLength(count);
 expect(vi.mocked(fetch).mock.calls.every(([url,init])=>String(url).startsWith('/api/')&&init?.method!=='POST')).toBe(true);
 expect(screen.getByText(vuln.shortDescription)).toBeVisible();
 expect(screen.getByText(record.sha256!)).toBeVisible();
 expect(screen.getByTestId('intelligence-panel')).toBeVisible();
});
