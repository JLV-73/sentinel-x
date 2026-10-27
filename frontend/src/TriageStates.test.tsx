import {render,screen,fireEvent,waitFor,within,act} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import App from './App';
import {triageResult,triageItem,emptySource} from './test/triageFixtures';
import {defaultResponse,json} from './test/fixtures';
import type {IntelligenceState,NvdData,EpssData} from './types';
vi.mock('./components/Charts',()=>({TrendChart:()=>null,VendorChart:()=>null}));
beforeEach(()=>{window.location.hash='triage';});
afterEach(()=>vi.unstubAllGlobals());
it('labels the exact triage snapshot NO DATA even when the independent summary reports real data',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/triage?')?json(triageResult({data_mode:'NO DATA',catalog_total:0,total:0,pages:1,items:[],cisa_provenance:null})):defaultResponse(url)));
 render(<App/>);await screen.findByText('Aucun catalogue importé');
 expect(within(screen.getByTestId('triage-results')).getByTestId('triage-data-mode')).toHaveAttribute('data-mode','NO DATA');
 expect(screen.queryByTestId('triage-next')).not.toBeInTheDocument();
});
it('shows read failure without fabricated rows and retries with local GET only',async()=>{
 let failed=true;vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/triage?')?failed?json({detail:'Local snapshot unavailable'},503):json(triageResult()):defaultResponse(url)));
 render(<App/>);expect(await screen.findByRole('alert')).toHaveTextContent('La base locale est indisponible');expect(screen.queryByTestId('triage-row-CVE-2026-1234')).not.toBeInTheDocument();
 failed=false;fireEvent.click(screen.getByRole('button',{name:'Réessayer'}));await screen.findByTestId('triage-row-CVE-2026-1234');
 expect(screen.queryByTestId('nvd-action')).not.toBeInTheDocument();
 for(const [url,options] of vi.mocked(fetch).mock.calls){expect(url).toMatch(/^\/api\//);expect(options?.method??'GET').toBe('GET');}
});
it('rejects a late older filter response even if the transport ignores AbortSignal',async()=>{
 const releases:((r:Response)=>void)[]=[];vi.stubGlobal('fetch',vi.fn((url:string)=>url.startsWith('/api/triage?')?new Promise<Response>(resolve=>releases.push(resolve)):Promise.resolve(defaultResponse(url))));
 render(<App/>);expect(screen.getByTestId('triage-results')).toHaveAttribute('aria-busy','true');expect(screen.getByRole('status')).toHaveTextContent('Lecture du renseignement local');
 await waitFor(()=>expect(releases).toHaveLength(1));fireEvent.change(screen.getByTestId('triage-search'),{target:{value:'new query'}});fireEvent.click(screen.getByTestId('triage-apply'));await waitFor(()=>expect(releases).toHaveLength(2));
 await act(async()=>releases[1](json(triageResult({total:0,pages:1,items:[]}))));expect(await screen.findByText('Aucune entrée correspondante')).toBeVisible();
 await act(async()=>releases[0](json(triageResult())));expect(screen.queryByTestId('triage-row-CVE-2026-1234')).not.toBeInTheDocument();expect(screen.getByText('Aucune entrée correspondante')).toBeVisible();
 expect(screen.getByTestId('triage-next')).toBeDisabled();expect(screen.getByTestId('triage-prev')).toBeDisabled();
});
it('renders all source states, missing values and nullable criteria without a synthetic zero or risk class',async()=>{
 const states:IntelligenceState[]=['not_requested','available','absent','unavailable','stale'];
 const items=states.map((state,index)=>{const item=triageItem();const id=`CVE-2026-100${index}`;return {...item,cve_id:id,kev:{...item.kev,cveID:id},nvd:{...emptySource<NvdData>(),state,stale:state==='stale'},epss:{...emptySource<EpssData>(),state,stale:state==='stale'},indicators:{recent_kev:false,cvss_threshold_met:null,epss_threshold_met:null,nvd_needs_enrichment:false,epss_needs_enrichment:false}};});
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/triage?')?json(triageResult({items})):defaultResponse(url)));
 render(<App/>);
 for(const [index,state] of states.entries()){const row=await screen.findByTestId(`triage-row-CVE-2026-100${index}`);expect(within(row).getByTestId('triage-nvd-state')).toHaveAttribute('data-state',state);expect(within(row).getByTestId('triage-epss-state')).toHaveAttribute('data-state',state);expect(within(row).getByTestId('triage-probability')).toHaveTextContent('Non disponible');expect(within(row).getByTestId('triage-criteria')).toHaveTextContent('Aucun critère rempli / non défini');}
});
it('displays retained stale/unavailable threshold matches and every CVSS metric without using percentile as probability',async()=>{
 const item=triageItem();item.epss={...item.epss,state:'unavailable',stale:true,retained_after_error:true,data:{...item.epss.data!,epss:.6,percentile:.001}};item.indicators={...item.indicators,cvss_threshold_met:true,epss_threshold_met:true,epss_needs_enrichment:true};
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/triage?')?json(triageResult({items:[item]})):defaultResponse(url)));
 render(<App/>);const row=await screen.findByTestId('triage-row-CVE-2026-1234');expect(within(row).getByTestId('triage-probability')).toHaveTextContent('60');expect(within(row).getByTestId('triage-percentile')).toHaveTextContent('0,1');expect(within(row).getByTestId('triage-criteria')).toHaveTextContent('Seuil CVSS atteint');expect(within(row).getByTestId('triage-criteria')).toHaveTextContent('Seuil de probabilité EPSS atteint');expect(within(row).getAllByTestId(/cvss-value-/)).toHaveLength(2);
 fireEvent.click(screen.getByTestId('language-en'));expect(within(row).getByTestId('triage-epss-state')).toHaveTextContent('Unavailable');expect(within(row).getByTestId('triage-epss-state')).toHaveTextContent('Stale');expect(within(row).getAllByText(/Last validated values retained/)).toHaveLength(2);
});
