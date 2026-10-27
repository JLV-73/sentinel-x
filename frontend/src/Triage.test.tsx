import {render,screen,within,fireEvent,waitFor} from '@testing-library/react';
import {triageResult,triageItem,emptySource} from './test/triageFixtures';
import type {NvdData,EpssData} from './types';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import App from './App';
import {defaultResponse,json} from './test/fixtures';
vi.mock('./components/Charts',()=>({TrendChart:()=>null,VendorChart:()=>null}));
beforeEach(()=>{window.location.hash='triage';vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/triage?')?json({data_mode:'NO DATA',as_of_utc:'2026-10-27T12:00:00Z',catalog_total:0,total:0,page:1,pages:1,page_size:20,filters:{},cisa_provenance:null,items:[]}):defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it('keeps sidebar navigation numbering sequential after adding triage',async()=>{
 const {container}=render(<App/>);await screen.findByTestId('triage-view');
 expect([...container.querySelectorAll('.sidebar .nav-number')].map(node=>node.textContent)).toEqual(['01','02','03','04']);
});

it('opens the dedicated read-only triage route without replacing the existing catalogue',async()=>{
 render(<App/>);
 expect(screen.getByRole('link',{name:/Triage/})).toHaveAttribute('href','#triage');
 expect(await screen.findByTestId('triage-view')).toBeVisible();
 expect(await screen.findByText('Aucun catalogue importé')).toBeVisible();
 expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/api/triage?'),expect.objectContaining({cache:'no-store'}));
 expect(screen.getByRole('link',{name:/Renseignement cyber/})).toHaveAttribute('href','#intelligence');
 for(const [url,options] of vi.mocked(fetch).mock.calls){expect(url).toMatch(/^\/api\//);expect(options?.method??'GET').toBe('GET');}
});


it('applies AND filters with EPSS percent converted once, then preserves page, draft and CVE through FR/EN and detail return',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>{if(url.startsWith('/api/triage?')){const params=new URL(url,'http://localhost').searchParams;return json(triageResult({page:Number(params.get('page')??1)}));}return defaultResponse(url);}));
 render(<App/>);await screen.findByTestId('triage-row-CVE-2026-1234');
 const set=(id:string,value:string)=>fireEvent.change(screen.getByTestId(id),{target:{value}});
 set('triage-search','100%_literal');set('triage-added-since','2026-10-01');set('triage-added-until','2026-10-27');set('triage-cvss-availability','scored');set('triage-cvss-min','0');set('triage-epss-percent','12.5');set('triage-nvd-filter','stale');set('triage-epss-filter','needs_attention');set('triage-recent-days','7');set('triage-sort','asc');fireEvent.click(screen.getByTestId('triage-recent-only'));fireEvent.click(screen.getByTestId('triage-apply'));
 await waitFor(()=>expect(fetch).toHaveBeenCalledWith(expect.stringContaining('epss_min=0.125'),expect.anything()));
 const url=vi.mocked(fetch).mock.calls.filter(([u])=>String(u).startsWith('/api/triage?')).at(-1)![0];const params=new URL(String(url),'http://localhost').searchParams;
 expect(Object.fromEntries(params)).toMatchObject({q:'100%_literal',added_since:'2026-10-01',added_until:'2026-10-27',cvss_availability:'scored',cvss_min:'0',epss_min:'0.125',nvd_state:'stale',epss_state:'needs_attention',recent_days:'7',recent_only:'true',sort:'asc',page:'1'});
 fireEvent.click(await screen.findByTestId('triage-next'));await screen.findByText('Page 2 sur 3');
 set('triage-search','unsent draft');const calls=vi.mocked(fetch).mock.calls.length;
 fireEvent.click(screen.getByTestId('language-en'));expect(vi.mocked(fetch).mock.calls).toHaveLength(calls);expect(screen.getByTestId('triage-search')).toHaveValue('unsent draft');expect(screen.getByText('Page 2 of 3')).toBeVisible();expect(screen.getByTestId('triage-added-since')).toHaveValue('2026-10-01');
 fireEvent.click(screen.getByTestId('triage-open-detail'));expect(await screen.findByRole('heading',{level:1,name:/CVE Inspector.*CVE-2026-1234/})).toBeVisible();
 fireEvent.click(screen.getByTestId('language-fr'));expect(window.location.hash).toBe('#cve/CVE-2026-1234');
 fireEvent.click(screen.getByTestId('detail-back'));await screen.findByText('Page 2 sur 3');expect(window.location.hash).toBe('#triage');expect(screen.getByTestId('triage-search')).toHaveValue('unsent draft');expect(screen.getByTestId('triage-epss-percent')).toHaveValue('12.5');
 fireEvent.click(screen.getByTestId('triage-reset'));await waitFor(()=>expect(screen.getByTestId('triage-search')).toHaveValue(''));await screen.findByText('Page 1 sur 3');
 expect(screen.getByText(/valeurs conservées.*seuils/i)).toBeVisible();
});

it('keeps every original CVSS metric, zero EPSS, percentile and retained source states separate',async()=>{
 const item=triageItem();const missing={...triageItem(),cve_id:'CVE-2026-9999',kev:{...item.kev,cveID:'CVE-2026-9999'},nvd:emptySource<NvdData>(),epss:emptySource<EpssData>(),indicators:{...item.indicators,recent_kev:false,nvd_needs_enrichment:true,epss_needs_enrichment:true}};
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/triage?')?json(triageResult({items:[item,missing]})):defaultResponse(url)));
 render(<App/>);
 const row=await screen.findByTestId('triage-row-CVE-2026-1234');
 expect(within(row).getByText('CVSS 3.1')).toBeVisible();expect(within(row).getByText('CVSS 4.0')).toBeVisible();
 expect(within(row).getByText('nvd@nist.gov')).toBeVisible();expect(within(row).getByText('vendor@example.test')).toBeVisible();
 expect(within(row).getByTestId('cvss-value-0')).toHaveTextContent('0');expect(within(row).getByTestId('cvss-value-1')).toHaveTextContent('9,8');
 expect(within(row).getByTestId('triage-probability')).toHaveTextContent(/^0\s*%$/);expect(within(row).getByTestId('triage-percentile')).toHaveTextContent('82,3');
 const state=within(row).getByTestId('triage-nvd-state');expect(state).toHaveAttribute('data-state','unavailable');expect(state).toHaveAttribute('data-stale','true');expect(state).toHaveTextContent('Indisponible');expect(state).toHaveTextContent('Ancien');
 expect(within(row).getByText(/valeurs validées conservées après erreur/)).toBeVisible();
 expect(within(row).getByTestId('triage-nvd-source-date')).toHaveAttribute('datetime','2026-10-19T23:00:00Z');expect(within(row).getByTestId('triage-epss-source-date')).toHaveAttribute('datetime','2026-10-26');
 expect(within(row).getByTestId('triage-nvd-collected')).toHaveAttribute('datetime','2026-10-20T12:00:00Z');
 expect(within(row).queryByText(/Seuil CVSS atteint/)).not.toBeInTheDocument();
 expect(within(screen.getByTestId('triage-row-CVE-2026-9999')).getByTestId('triage-probability')).toHaveTextContent('Non disponible');
 fireEvent.click(within(row).getAllByText('Provenance de la collecte')[0]);
 expect(within(row).getByText('b'.repeat(64))).toBeVisible();expect(within(row).getByRole('link',{name:/services.nvd.nist.gov/})).toHaveAttribute('href',item.nvd.provenance!.url);
 expect(within(row).getByRole('link',{name:'NVD'})).toHaveAttribute('href','https://nvd.nist.gov/vuln/detail/CVE-2026-1234');
 expect(within(row).getByRole('link',{name:'FIRST'})).toHaveAttribute('href','https://www.first.org/epss/');
 expect(screen.getByText(/ne démontre pas que votre organisation est vulnérable/)).toBeVisible();
});
