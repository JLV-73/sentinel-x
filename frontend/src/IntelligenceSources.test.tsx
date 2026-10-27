import {act,render,screen,within,fireEvent,waitFor} from '@testing-library/react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import App from './App';
import {defaultResponse,json,record} from './test/fixtures';
import type {IntelligenceStatus,IntelligenceAttempt} from './types';
const success:IntelligenceAttempt={id:21,source:'epss',status:'success',started_at:'2026-10-26T10:00:00Z',finished_at:'2026-10-26T10:00:01Z',requested:2,available:2,absent:0,failed:0,error:null,provenances:[{source:'epss',url:'https://api.first.org/data/v1/epss?cve=CVE-2026-1234',sha256:'e'.repeat(64),collected_at:'2026-10-26T10:00:00Z',raw_file:'intelligence_raw/epss/test.json'}]};
const coverage={available:1,with_scores:1,absent:0,unavailable:0,stale:0,not_requested:1};
const initial:IntelligenceStatus={nvd:{...coverage,source:'nvd',last_attempt:null,last_success:null,history:[],freshness_hours:168,busy:false,endpoint:'https://services.nvd.nist.gov/rest/json/cves/2.0'},epss:{...coverage,source:'epss',last_attempt:success,last_success:success,history:[success],freshness_hours:24,busy:false,endpoint:'https://api.first.org/data/v1/epss'}};
beforeEach(()=>{window.location.hash='data';vi.stubGlobal('fetch',vi.fn(async(url:string)=>url==='/api/intelligence/status'?json(initial):defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());

it('keeps verified EPSS read-back when a concurrent CISA revision read finishes late, then accepts a new manual refresh',async()=>{
 let reads=0;let releaseEpss!:(response:Response)=>void;let releaseOld!:(response:Response)=>void;
 let oldSignal:AbortSignal|undefined;
 const verified={...initial,epss:{...initial.epss,available:2,with_scores:2,not_requested:0}};
 const refreshed={...verified,epss:{...verified.epss,available:1,with_scores:1,stale:1}};
 vi.stubGlobal('fetch',vi.fn((url:string,init?:RequestInit)=>{
  if(url==='/api/intelligence/epss'&&init?.method==='POST')return new Promise<Response>(resolve=>{releaseEpss=resolve;});
  if(url==='/api/sync'&&init?.method==='POST')return Promise.resolve(json(record));
  if(url==='/api/intelligence/status'){
   reads++;
   // Deliberately ignore abort: a late response must not undo exact read-back.
   if(reads===2){oldSignal=init?.signal as AbortSignal;return new Promise<Response>(resolve=>{releaseOld=resolve;});}
   return Promise.resolve(json(reads===1?initial:reads===3?verified:refreshed));
  }
  return Promise.resolve(defaultResponse(url));
 }));
 render(<App/>);fireEvent.click(await screen.findByTestId('epss-action'));
 fireEvent.click(await screen.findByRole('button',{name:'Synchroniser maintenant'}));
 expect(await screen.findByText('Synchronisation vérifiée')).toBeVisible();
 await waitFor(()=>expect(reads).toBe(2));
 await act(async()=>releaseEpss(json(success)));
 expect(await screen.findByText('Résultat de la source vérifié par relecture locale.')).toBeVisible();
 expect(screen.getByTestId('epss-coverage')).toHaveTextContent('2 / 2');
 await act(async()=>releaseOld(json(initial)));
 expect(screen.getByTestId('epss-coverage')).toHaveTextContent('2 / 2');
 expect(oldSignal?.aborted).toBe(true);
 expect(screen.getByTestId('nvd-coverage')).toHaveTextContent('1 / 2');
 expect(within(screen.getByTestId('source-nvd')).queryByText('Résultat de la source vérifié par relecture locale.')).not.toBeInTheDocument();
 const refresh=screen.getByRole('button',{name:'Relire l’état des sources'});expect(refresh).toBeEnabled();fireEvent.click(refresh);
 await waitFor(()=>expect(reads).toBe(4));
 await waitFor(()=>expect(screen.getByTestId('epss-coverage')).toHaveTextContent('1 / 2'));
 expect(screen.getByTestId('nvd-coverage')).toHaveTextContent('1 / 2');
 expect(vi.mocked(fetch).mock.calls.filter(([,init])=>init?.method==='POST').map(([url])=>url)).toEqual(['/api/intelligence/epss','/api/sync']);
});

it('shows a localized deferred lease warning beside verified EPSS data while respecting backend busy status',async()=>{
 let posted=false;
 const technical='lease release failed <script>unsafe detail</script>';
 const next={...initial,epss:{...initial.epss,available:2,with_scores:2,not_requested:0,busy:true}};
 vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(url==='/api/intelligence/epss'&&init?.method==='POST'){posted=true;return json({...success,cleanup_deferred:true,cleanup_warning:technical});}
  return url==='/api/intelligence/status'?json(posted?next:initial):defaultResponse(url);
 }));render(<App/>);fireEvent.click(await screen.findByTestId('epss-action'));
 expect(await screen.findByText('Résultat de la source vérifié par relecture locale.')).toBeVisible();
 const warning=within(screen.getByTestId('source-epss')).getByRole('alert');
 expect(warning).toHaveTextContent('La libération du verrou de la source est différée');
 expect(warning).toHaveTextContent('jusqu’à l’expiration du verrou');
 expect(screen.getByTestId('epss-coverage')).toHaveTextContent('2 / 2');
 expect(screen.getByTestId('epss-action')).toBeDisabled();
 expect(screen.getByRole('button',{name:'Synchroniser maintenant'})).toBeEnabled();
 expect(within(screen.getByTestId('source-nvd')).queryByRole('alert')).not.toBeInTheDocument();
 expect(screen.queryByText(technical)).not.toBeInTheDocument();
 const count=vi.mocked(fetch).mock.calls.length;fireEvent.click(screen.getByTestId('language-en'));
 expect(warning).toHaveTextContent('Source lease release is deferred');
 expect(screen.getByText('Source result verified by local read-back.')).toBeVisible();
 expect(vi.mocked(fetch).mock.calls).toHaveLength(count);
});

it('retains source coverage when local status refresh fails and localizes its warning',async()=>{
 let reads=0;vi.stubGlobal('fetch',vi.fn(async(url:string)=>{
  if(url==='/api/intelligence/status'){if(++reads>1)throw new TypeError('Local connection lost');return json(initial);}return defaultResponse(url);
 }));render(<App/>);await screen.findByTestId('source-epss');fireEvent.click(screen.getByRole('button',{name:'Relire l’état des sources'}));
 expect(await screen.findByText('L’état des sources n’a pas pu être relu. La dernière couverture connue reste affichée.')).toBeVisible();
 expect(screen.getByTestId('source-epss')).toBeVisible();fireEvent.click(screen.getByTestId('language-en'));
 expect(screen.getByText('Source status could not be re-read. Last known coverage remains displayed.')).toBeVisible();
});
it('displays a failed EPSS attempt without erasing the previous success or confusing it with CISA',async()=>{
 let posted=false;const failure={...success,id:23,status:'failed' as const,available:0,failed:2,error:'FIRST upstream 503'};
 vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(url==='/api/intelligence/epss'&&init?.method==='POST'){posted=true;return json({detail:{error:failure.error,source:'epss'}},502);}
  if(url==='/api/intelligence/status')return json(posted?{...initial,epss:{...initial.epss,last_attempt:failure,history:[failure,success],available:0,unavailable:2}}:initial);return defaultResponse(url);
 }));render(<App/>);fireEvent.click(await screen.findByTestId('epss-action'));
 expect(await screen.findByText('Échec de la requête à la source. Inspectez la dernière tentative ; les données validées sont conservées.')).toBeVisible();
 const source=screen.getByTestId('source-epss');expect(within(source).getAllByText(success.provenances[0].sha256).length).toBeGreaterThan(0);
 expect(within(source).getAllByText('FIRST upstream 503').length).toBeGreaterThan(0);
 expect(within(source).getByText(/"error": "FIRST upstream 503"/)).toBeInTheDocument();
 expect(await screen.findByText(record.sha256!)).toBeVisible();expect(screen.queryByText('Synchronisation vérifiée')).not.toBeInTheDocument();
});
it('disables only the busy EPSS source and includes the original NVD notice',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url==='/api/intelligence/status'?json({...initial,epss:{...initial.epss,busy:true}}):defaultResponse(url)));
 render(<App/>);expect(await screen.findByTestId('epss-action')).toBeDisabled();expect(await screen.findByRole('button',{name:'Synchroniser maintenant'})).toBeEnabled();
 const notice=screen.getByText('This product uses data from the NVD API but is not endorsed or certified by the NVD.');expect(notice).toHaveAttribute('lang','en');
 fireEvent.click(screen.getByTestId('language-en'));expect(notice).toBeVisible();
});

it('keeps independent NVD/EPSS coverage and provenance beside the unchanged CISA control',async()=>{
 render(<App/>);const nvd=await screen.findByTestId('source-nvd');const epss=screen.getByTestId('source-epss');
 expect(within(nvd).getByText('Non demandé')).toBeVisible();expect(within(nvd).getByTestId('nvd-coverage')).toHaveTextContent('1 / 2');expect(within(nvd).getByText(/NVD est collecté par CVE/)).toBeVisible();
 expect(within(epss).getByText('Entrées avec scores validés (valeurs conservées / anciennes incluses)')).toBeVisible();
 expect(within(epss).getAllByText('e'.repeat(64)).length).toBeGreaterThan(0);
 expect(await screen.findByText(record.sha256!)).toBeVisible();expect(screen.getByRole('button',{name:'Synchroniser maintenant'})).toBeEnabled();
 expect(vi.mocked(fetch).mock.calls.every(([,init])=>init?.method!=='POST')).toBe(true);
});
it('collects EPSS only by explicit POST and verifies a partial result, preserving source history across FR/EN',async()=>{
 let posted=false;let release:(r:Response)=>void=()=>{};
 const partial={...success,id:22,status:'partial' as const,available:1,failed:1,error:'FIRST batch timeout'};
 const next={...initial,epss:{...initial.epss,last_attempt:partial,last_success:success,history:[partial,success],unavailable:1,not_requested:0}};
 vi.stubGlobal('fetch',vi.fn((url:string,init?:RequestInit)=>{
  if(url==='/api/intelligence/epss'&&init?.method==='POST'){posted=true;return new Promise<Response>(resolve=>{release=resolve;});}
  return Promise.resolve(url==='/api/intelligence/status'?json(posted?next:initial):defaultResponse(url));
 }));render(<App/>);const button=await screen.findByTestId('epss-action');fireEvent.click(button);fireEvent.click(button);expect(button).toBeDisabled();
 fireEvent.click(screen.getByTestId('language-en'));release(json(partial));
 expect(await screen.findByText('Partial result verified — some requests failed; see the source journal.')).toBeVisible();
 expect(vi.mocked(fetch).mock.calls.filter(([,init])=>init?.method==='POST')).toHaveLength(1);
 expect(fetch).toHaveBeenCalledWith('/api/intelligence/epss',expect.objectContaining({method:'POST',headers:{'X-Sentinel-Request':'sync'}}));
 expect(vi.mocked(fetch).mock.calls.filter(([url])=>url==='/api/intelligence/status')).toHaveLength(2);
 const source=screen.getByTestId('source-epss');const history=within(source).getByText('Source attempt history').closest('details')!;
 fireEvent.click(within(history).getByText('Source attempt history'));expect(history.open).toBe(true);
 fireEvent.click(screen.getByTestId('language-fr'));expect(history.open).toBe(true);expect(screen.getByText('Résultat partiel vérifié — certaines requêtes ont échoué ; consulter le journal de la source.')).toBeVisible();
 expect(within(source).getAllByText('FIRST batch timeout').length).toBeGreaterThan(0);
});
