import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import App from './App';
import {initialTriageFilters,triageQuery} from './triage';
import {triageResult} from './test/triageFixtures';
import {defaultResponse,json} from './test/fixtures';
vi.mock('./components/Charts',()=>({TrendChart:()=>null,VendorChart:()=>null}));
beforeEach(()=>{window.location.hash='triage';vi.stubGlobal('fetch',vi.fn(async(url:string)=>url.startsWith('/api/triage?')?json(triageResult()):defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it.each(['-1','100.01','Infinity','NaN',' ','0x10'])('rejects invalid EPSS percent %s without silently clamping',value=>{
 expect(()=>triageQuery({...initialTriageFilters,epss_percent:value})).toThrow();
});
it.each(['-0.1','10.001','Infinity','NaN'])('rejects invalid CVSS %s',value=>{
 expect(()=>triageQuery({...initialTriageFilters,cvss_min:value})).toThrow();
});
it.each(['0','3651','1.5',''])('requires whole UTC recency days 1..3650: %s',value=>{
 expect(()=>triageQuery({...initialTriageFilters,recent_days:value})).toThrow();
});
it.each([{added_since:'2026-02-30'},{added_since:'2026-1-01'},{added_since:'0000-01-01'},{added_since:'2026-10-28',added_until:'2026-10-27'}])('rejects invalid ISO dates or reversed ranges %o',patch=>{
 expect(()=>triageQuery({...initialTriageFilters,...patch})).toThrow();
});
it('accepts inclusive zero/full-scale bounds and French decimal input without converting percentile',()=>{
 expect(triageQuery({...initialTriageFilters,epss_percent:'0',cvss_min:'0'})).toMatchObject({epss_min:0,cvss_min:0});
 expect(triageQuery({...initialTriageFilters,epss_percent:'100',cvss_min:'10',recent_days:'3650'})).toMatchObject({epss_min:1,cvss_min:10,recent_days:3650});
 expect(triageQuery({...initialTriageFilters,epss_percent:'12,5'})).toMatchObject({epss_min:0.125});
 expect(triageQuery(initialTriageFilters)).not.toHaveProperty('epss_min');
});
it('keeps invalid text visible and localized, blocks GET, and applies a correction without losing other filters',async()=>{
 render(<App/>);await screen.findByTestId('triage-row-CVE-2026-1234');
 const input=screen.getByTestId('triage-epss-percent');fireEvent.change(input,{target:{value:'101'}});const calls=vi.mocked(fetch).mock.calls.length;fireEvent.click(screen.getByTestId('triage-apply'));
 expect(input).toHaveValue('101');expect(input).toHaveAttribute('aria-invalid','true');expect(await screen.findByTestId('triage-error-epss_percent')).toHaveTextContent('0 à 100');expect(vi.mocked(fetch).mock.calls).toHaveLength(calls);
 fireEvent.click(screen.getByTestId('language-en'));expect(screen.getByTestId('triage-error-epss_percent')).toHaveTextContent('0 to 100');expect(input).toHaveValue('101');
 fireEvent.change(input,{target:{value:'12.5'}});fireEvent.change(screen.getByTestId('triage-added-since'),{target:{value:'2026-10-28'}});fireEvent.change(screen.getByTestId('triage-added-until'),{target:{value:'2026-10-27'}});fireEvent.click(screen.getByTestId('triage-apply'));expect(vi.mocked(fetch).mock.calls).toHaveLength(calls);expect(screen.getByTestId('triage-error-added_until')).toBeVisible();
 fireEvent.change(screen.getByTestId('triage-added-until'),{target:{value:'2026-10-28'}});fireEvent.click(screen.getByTestId('triage-apply'));
 await waitFor(()=>expect(fetch).toHaveBeenCalledWith(expect.stringContaining('epss_min=0.125'),expect.anything()));expect(screen.queryByTestId('triage-error-epss_percent')).not.toBeInTheDocument();
});
