import {afterEach,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render,screen} from '@testing-library/react';
import {LocaleProvider,localeKey} from './i18n';
import DiscoveryReal from './components/DiscoveryReal';
const cap={schema:'fortress.discovery-capability/1',lab:true,live:true};
const partial={schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'scope_blocked',requests:0,bytes:0,pages:[],relations:[],resources:[],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion']};
afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks();localStorage.clear();});
async function ready(){
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText(/Discovery HTTPS origin/i),{target:{value:'https://example.org'}});
 fireEvent.click(screen.getByRole('button',{name:/check discovery capability/i}));
 await screen.findByText(/live capability verified/i);
 fireEvent.click(screen.getByLabelText(/I confirm I am authorized/i));
}
it('validates every budget, resets consent after changes, and posts chosen values once',async()=>{
 localStorage.setItem(localeKey,'en');
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).endsWith('/discovery/capability')?cap:String(u).endsWith('/mvp/capability')?{capability:'a'.repeat(32)}:partial)));
 await ready();
 const start=screen.getByRole('button',{name:/start discovery/i});
 const pages=screen.getByLabelText(/^Pages /);
 for(const invalid of ['', '1.5', '-1']){fireEvent.change(pages,{target:{value:invalid}});expect(screen.getByRole('alert')).toHaveTextContent(/invalid budgets/i);expect(start).toBeDisabled();}
 fireEvent.change(pages,{target:{value:'5'}});
 for(const [label,invalid,valid] of [[/^Pages /,'6','4'],[/^Requests /,'0','9'],[/^Depth /,'2','0'],[/^Interval /,'0','2'],[/^Bytes per page /,'524289','1000'],[/^Total bytes /,'3145729','2000'],[/^Duration /,'121','90']] as const){
  const input=screen.getByLabelText(label);fireEvent.change(input,{target:{value:invalid}});expect(screen.getByRole('alert')).toHaveTextContent(/invalid budgets/i);expect(start).toBeDisabled();
  fireEvent.change(input,{target:{value:valid}});expect(screen.queryByRole('alert')).not.toBeInTheDocument();
 }
 expect(start).toBeDisabled();fireEvent.click(screen.getByLabelText(/I confirm I am authorized/i));fireEvent.click(start);
 await screen.findByTitle(/discovery report preview/i);expect(screen.getByText(/partial or incomplete result/i)).toBeInTheDocument();
 const posts=fetcher.mock.calls.filter(([u])=>String(u).endsWith('/discovery/live'));expect(posts).toHaveLength(1);
 expect(JSON.parse(String(posts[0][1]?.body))).toEqual({authorized:true,target:'https://example.org',routes:['/'],limits:{pages:4,requests:9,depth:0,interval:2,page_bytes:1000,total_bytes:2000,seconds:90}});
});
it('cleans the timer on invalidation while a capability fetch ignores abort',async()=>{
 localStorage.setItem(localeKey,'en');vi.useFakeTimers();
 vi.spyOn(globalThis,'fetch').mockImplementation(()=>new Promise<Response>(()=>{}));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);expect(vi.getTimerCount()).toBe(0);
 fireEvent.click(screen.getByRole('button',{name:/check discovery capability/i}));expect(vi.getTimerCount()).toBe(1);
 fireEvent.change(screen.getByLabelText(/Discovery HTTPS origin/i),{target:{value:'https://example.org'}});
 expect(vi.getTimerCount()).toBe(0);
 await act(async()=>{await vi.advanceTimersByTimeAsync(150000);});expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
