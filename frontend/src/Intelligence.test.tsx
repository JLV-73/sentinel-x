import {render,screen,within,fireEvent,waitFor} from '@testing-library/react';
import {afterEach,beforeEach,it,expect,vi} from 'vitest';
import App from './App';
import type {Intelligence,IntelligenceProvenance,IntelligenceAttempt,SourceData,NvdData,EpssData} from './types';
import {json,defaultResponse,vuln} from './test/fixtures';
// Test-only official-shaped records; no application fallback data.
const provenance:IntelligenceProvenance={source:'nvd',url:'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-1234',sha256:'b'.repeat(64),collected_at:'2026-10-26T12:00:00Z',raw_file:'intelligence_raw/nvd/test.json'};
const attempt:IntelligenceAttempt={id:11,source:'nvd',status:'success',started_at:'2026-10-26T12:00:00Z',finished_at:'2026-10-26T12:00:01Z',requested:1,available:1,absent:0,failed:0,error:null,provenances:[provenance]};
const empty:SourceData<never>={state:'not_requested',stale:false,retained_after_error:false,collected_at:null,source_date:null,data:null,provenance:null,last_attempt:null,last_success:null};
const nvd:SourceData<NvdData>={...empty,state:'available',collected_at:provenance.collected_at,source_date:'2026-10-25T10:00:00Z',provenance,last_attempt:attempt,last_success:attempt,data:{id:vuln.cveID,published:'2026-10-20T00:00:00Z',last_modified:'2026-10-25T10:00:00Z',vuln_status:'Analyzed',descriptions:[{lang:'en',value:'Original NVD description.'}],cvss:[{version:'3.1',base_score:0,base_severity:null,vector:'CVSS:3.1/AV:N',source:'cna@example.test',type:'Primary',record_modified:'2026-10-25T10:00:00Z'},{version:'4.0',base_score:9.3,base_severity:'CRITICAL',vector:'CVSS:4.0/AV:N',source:'nvd@nist.gov',type:'Secondary',record_modified:'2026-10-25T10:00:00Z'}],weaknesses:[{description:[{lang:'en',value:'CWE-79'}]}],references:[{url:'https://example.test/advisory'}],configurations:[{nodes:[{cpeMatch:[{criteria:'cpe:2.3:a:example:product:*:*:*:*:*:*:*:*'}]}]}]}};
const epss:SourceData<EpssData>={...empty,state:'available',collected_at:'2026-10-26T12:01:00Z',source_date:'2026-10-26',provenance:{...provenance,source:'epss',url:'https://api.first.org/data/v1/epss?cve=CVE-2026-1234',sha256:'c'.repeat(64)},data:{cve:vuln.cveID,epss:0.01234,percentile:0.87,date:'2026-10-26'}};
let current:Intelligence={cve_id:vuln.cveID,nvd,epss};
function mount(){render(<App/>);}
beforeEach(()=>{window.location.hash=`cve/${vuln.cveID}`;current={cve_id:vuln.cveID,nvd,epss};vi.stubGlobal('fetch',vi.fn(async(url:string)=>url===`/api/intelligence/${vuln.cveID}`?json(current):defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());

it('keeps score values when NVD fails and re-reading local data also fails',async()=>{
 let posted=false;vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(init?.method==='POST'){posted=true;return json({detail:'NVD source timeout'},502);}
  if(url===`/api/intelligence/${vuln.cveID}`){if(posted)throw new TypeError('Local read failed');return json(current);}return defaultResponse(url);
 }));mount();fireEvent.click(await screen.findByTestId('nvd-action'));
 expect(await screen.findByText(/Impossible de confirmer ce résultat par relecture locale/)).toBeVisible();
 expect(screen.getAllByTestId('cvss-score')).toHaveLength(2);expect(screen.getByText('NVD source timeout')).toBeInTheDocument();
 expect(screen.queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
});
it('keeps local detail and source warning usable when intelligence is offline',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/intelligence/')?json({detail:'Endpoint not installed'},404):defaultResponse(url)));
 mount();expect(await screen.findByText(/Point d’accès au renseignement indisponible/)).toBeVisible();expect(screen.getByText(vuln.shortDescription)).toBeVisible();
 expect(screen.queryByTestId('cvss-score')).not.toBeInTheDocument();expect(screen.queryByTestId('epss-score')).not.toBeInTheDocument();
});


it('adds labelled local indicators for only visible CVEs without changing catalogue requests',async()=>{
 window.location.hash='intelligence';
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/intelligence?')?json({items:{[vuln.cveID]:{...current,epss:{...epss,state:'stale',stale:true}}}}):defaultResponse(url)));
 mount();expect(await screen.findByText('CVSS · Disponible')).toBeVisible();expect(screen.getByText('EPSS · Ancien')).toBeVisible();
 const calls=vi.mocked(fetch).mock.calls;const page=calls.find(([url])=>String(url).startsWith('/api/intelligence?'))!;
 expect(new URL(String(page[0]),'http://localhost').searchParams.get('cve')).toBe(vuln.cveID);
 expect(calls.some(([url])=>url==='/api/vulnerabilities?sort=desc&page=1&page_size=20')).toBe(true);
 expect(calls.every(([,init])=>init?.method!=='POST')).toBe(true);const count=calls.length;
 fireEvent.click(screen.getByTestId('language-en'));expect(screen.getByText('CVSS · Available')).toBeVisible();expect(screen.getByText('EPSS · Stale')).toBeVisible();expect(vi.mocked(fetch).mock.calls).toHaveLength(count);
});
it('keeps catalogue and CISA detail usable when the new endpoint is offline',async()=>{
 window.location.hash='intelligence';mount();
 expect(await screen.findByText('Enrichissement indisponible ; les résultats CISA restent inchangés.')).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:`Ouvrir ${vuln.cveID}`}));
 expect(await screen.findByText(vuln.shortDescription)).toBeVisible();
});


it.each(['not_requested','available','absent','unavailable','stale'] as const)('shows %s without manufacturing a score',async(state)=>{
 current={cve_id:vuln.cveID,nvd:{...empty,state},epss:{...empty,state,stale:state==='stale'}};
 mount();expect(await screen.findByTestId('nvd-state')).toHaveAttribute('data-state',state);
 expect(screen.getByTestId('epss-state')).toHaveAttribute('data-state',state);
 expect(screen.queryByTestId('epss-score')).not.toBeInTheDocument();expect(screen.queryByTestId('cvss-score')).not.toBeInTheDocument();
 if(state==='absent')expect(screen.getAllByText(/Ce n’est pas un score nul/)).toHaveLength(2);
});
it('displays a real EPSS zero, and keeps a scoreless NVD record distinct from absence',async()=>{
 current={...current,nvd:{...nvd,data:{...nvd.data!,cvss:[]}},epss:{...epss,data:{...epss.data!,epss:0,percentile:0}}};mount();
 expect(await screen.findByTestId('epss-score')).toHaveTextContent(/^0\s*%$/);expect(screen.getByTestId('epss-percentile')).toHaveTextContent('0');
 expect(screen.getByText('Aucune métrique CVSS publiée dans cette fiche NVD.')).toBeVisible();expect(screen.getByTestId('nvd-state')).toHaveAttribute('data-state','available');
});
it('retains failed-source values under a conspicuous warning across a language switch',async()=>{
 current={...current,nvd:{...nvd,state:'unavailable',retained_after_error:true,last_attempt:{...attempt,id:12,status:'failed',error:'NVD upstream timeout'}}};mount();
 const state=await screen.findByTestId('nvd-state');expect(within(state).getByRole('alert')).toHaveTextContent(/valeurs validées conservées après erreur/);
 expect(screen.getAllByTestId('cvss-score')).toHaveLength(2);fireEvent.click(screen.getByTestId('language-en'));
 expect(within(state).getByRole('alert')).toHaveTextContent(/retained after an error/);expect(within(state).getAllByText('NVD upstream timeout').length).toBeGreaterThan(0);
});
it('manually refreshes NVD once, with the guard header, then verifies the exact local record',async()=>{
 let release:(r:Response)=>void=()=>{};let posted=false;
 const next={...nvd,last_attempt:{...attempt,id:20},last_success:{...attempt,id:20}};
 vi.stubGlobal('fetch',vi.fn((url:string,init?:RequestInit)=>{
  if(url===`/api/intelligence/nvd/${vuln.cveID}?refresh=true`){posted=true;return new Promise<Response>(resolve=>{release=resolve;});}
  if(url===`/api/intelligence/${vuln.cveID}`)return Promise.resolve(json(posted?{...current,nvd:next}:current));
  return Promise.resolve(defaultResponse(url));
 }));mount();const button=await screen.findByTestId('nvd-action');fireEvent.click(button);fireEvent.click(button);
 expect(button).toBeDisabled();fireEvent.click(screen.getByTestId('language-en'));release(json(next));
 expect(await screen.findByText('Source result verified by local read-back.')).toBeVisible();
 const posts=vi.mocked(fetch).mock.calls.filter(([,init])=>init?.method==='POST');expect(posts).toHaveLength(1);expect(posts[0][1]?.headers).toEqual({'X-Sentinel-Request':'sync'});
 expect(vi.mocked(fetch).mock.calls.filter(([url])=>url===`/api/intelligence/${vuln.cveID}`)).toHaveLength(2);
 fireEvent.click(screen.getByTestId('language-fr'));expect(screen.getByText('Résultat de la source vérifié par relecture locale.')).toBeVisible();
});
it.each([true,false,undefined])('handles optional NVD deferred lease cleanup (%s) independently of verified durable data',async(deferred)=>{
 const technical='lease cleanup database error';
 vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(init?.method==='POST')return json({...nvd,cleanup_deferred:deferred,cleanup_warning:technical});
  return url===`/api/intelligence/${vuln.cveID}`?json(current):defaultResponse(url);
 }));mount();fireEvent.click(await screen.findByTestId('nvd-action'));
 expect(await screen.findByText('Résultat de la source vérifié par relecture locale.')).toBeVisible();
 expect(screen.getAllByTestId('cvss-score')).toHaveLength(2);
 const panel=screen.getByTestId('nvd-panel');
 if(deferred){
  expect(within(panel).getByRole('alert')).toHaveTextContent('La libération du verrou de la source est différée');
  fireEvent.click(screen.getByTestId('language-en'));
  expect(within(panel).getByRole('alert')).toHaveTextContent('Source lease release is deferred');
 } else expect(within(panel).queryByRole('alert')).not.toBeInTheDocument();
 expect(screen.queryByText(technical)).not.toBeInTheDocument();
 expect(within(screen.getByTestId('epss-state')).queryByRole('alert')).not.toBeInTheDocument();
});

it('uses cache-first fetch for an unrequested NVD entry and never claims success on a mismatched read-back',async()=>{
 current={...current,nvd:empty};vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(init?.method==='POST')return json(nvd);
  return url===`/api/intelligence/${vuln.cveID}`?json(current):defaultResponse(url);
 }));mount();fireEvent.click(await screen.findByRole('button',{name:'Collecter NVD pour cette CVE'}));
 expect(await screen.findByText(/Impossible de confirmer ce résultat par relecture locale/)).toBeVisible();
 expect(fetch).toHaveBeenCalledWith(`/api/intelligence/nvd/${vuln.cveID}?refresh=false`,expect.objectContaining({method:'POST'}));
 expect(screen.queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
});

it('reads local intelligence only and separates KEV, every CVSS entry and EPSS with provenance',async()=>{
 mount();const panel=await screen.findByTestId('intelligence-panel');
 expect(within(panel).getByRole('heading',{name:'CISA KEV · exploitation connue'})).toBeVisible();
 const cvss=await within(panel).findByTestId('nvd-panel');
 expect(within(cvss).getByText('CVSS 3.1')).toBeVisible();expect(within(cvss).getByText('CVSS 4.0')).toBeVisible();
 expect(within(cvss).getAllByTestId('cvss-score')[0]).toHaveTextContent('0');expect(within(cvss).getByText('9,3')).toBeVisible();
 expect(within(cvss).getByText('CRITICAL')).toBeVisible();expect(within(cvss).getByText('cna@example.test')).toBeVisible();expect(within(cvss).getByText('Secondary')).toBeVisible();
 expect(within(cvss).getByText('Original NVD description.')).toHaveAttribute('lang','en');
 expect(within(cvss).getByText('Texte officiel NVD — anglais')).toBeVisible();
 expect(within(cvss).getByText('CWE · données officielles')).toBeInTheDocument();expect(within(cvss).getByText('Produits / configurations CPE · JSON')).toBeInTheDocument();
 expect(within(panel).getByTestId('epss-score')).toHaveTextContent(/1,234\s*%/);
 expect(within(panel).getByTestId('epss-percentile')).toHaveTextContent('87');
 expect(within(panel).getByText(/Un rang relatif, pas une seconde probabilité/)).toBeVisible();
 expect(within(panel).getAllByText(/26 oct. 2026/).length).toBeGreaterThan(0);
 expect(within(panel).getAllByText(provenance.sha256).length).toBeGreaterThan(0);
 expect(vi.mocked(fetch).mock.calls.every(([,init])=>init?.method!=='POST')).toBe(true);
 fireEvent.click(screen.getByTestId('language-en'));expect(within(panel).getByTestId('epss-score')).toHaveTextContent('1.234%');expect(within(panel).getByText('Original NVD description.')).toHaveAttribute('lang','en');
});
