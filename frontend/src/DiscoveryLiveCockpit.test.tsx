import {it,expect,vi,afterEach} from 'vitest';
import {render,screen,fireEvent,cleanup,waitFor,act} from '@testing-library/react';
import {LocaleProvider,localeKey} from './i18n';
import DiscoveryReal from './components/DiscoveryReal';
afterEach(()=>{cleanup();localStorage.clear();vi.restoreAllMocks();});
const capability={schema:'fortress.discovery-capability/1',lab:true,live:true};
const blocked={schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'scope_blocked',requests:0,bytes:0,pages:[],relations:[],resources:[],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion']};
it.each([['fr','https://example.org'],['en','https://example.org'],['fr','https://example.org/'],['en','https://example.org/']] as const)('requires consent and posts the canonical scope (%s, %s)',async (locale,target)=>{
 localStorage.setItem(localeKey,locale);
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?capability:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:blocked)));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 const start=screen.getByRole('button',{name:/start discovery|démarrer discovery/i});
 fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:target}});
 expect(start).toBeDisabled();fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));
 await screen.findByText(/live capability verified|capacité réelle vérifiée/i);expect(start).toBeDisabled();
 expect(fetcher.mock.calls.filter(([u])=>String(u).endsWith('/discovery/live'))).toHaveLength(0);
 fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));expect(start).toBeEnabled();fireEvent.click(start);
 await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i);
 const post=fetcher.mock.calls.find(([u])=>String(u).endsWith('/discovery/live'))!;
 expect(fetcher.mock.calls.filter(([u])=>String(u).endsWith('/discovery/live'))).toHaveLength(1);
 expect(JSON.parse(String(post[1]?.body))).toEqual({authorized:true,target:'https://example.org/',routes:['/'],limits:{pages:5,requests:10,depth:1,interval:1,page_bytes:524288,total_bytes:3145728,seconds:120}});
 expect(fetcher.mock.calls.every(([u])=>String(u).startsWith('http://127.0.0.1:8007/'))).toBe(true);
 expect(screen.getByTitle(/discovery report preview|aperçu du rapport discovery/i).getAttribute('srcdoc')).toMatch(/scope|périmètre/i);
});
it('fails closed for malformed capability',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({...capability,extra:'secret'})));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));
 await waitFor(()=>expect(screen.getByRole('alert')).toBeInTheDocument());expect(screen.getByRole('button',{name:/start discovery|démarrer discovery/i})).toBeDisabled();
});
it('discards a late live response after scope changes even if fetch ignores abort',async()=>{
 let finish!:(value:Response)=>void;
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async u=>{
  if(String(u).endsWith('/discovery/live'))return await new Promise<Response>(resolve=>{finish=resolve;});
  return new Response(JSON.stringify(String(u).includes('/discovery/capability')?capability:{capability:'a'.repeat(32)}));
 });
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.org'}});
 fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
 fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
 await waitFor(()=>expect(fetcher.mock.calls.some(([u])=>String(u).endsWith('/discovery/live'))).toBe(true));
 const signal=fetcher.mock.calls.find(([u])=>String(u).endsWith('/discovery/live'))![1]!.signal!;
 fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://changed.example'}});expect(signal.aborted).toBe(true);
 await act(async()=>{finish(new Response(JSON.stringify(blocked)));});
 expect(screen.queryByTitle(/discovery report preview|aperçu du rapport discovery/i)).not.toBeInTheDocument();
 expect(screen.getByRole('button',{name:/start discovery|démarrer discovery/i})).toBeDisabled();
});
it('does not post if the capability disappears before launch',async()=>{
 let checks=0;const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?(++checks===1?capability:{...capability,live:false}):{capability:'a'.repeat(32)})));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.org'}});
 fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
 fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
 await screen.findByRole('alert');expect(fetcher.mock.calls.some(([u])=>String(u).endsWith('/discovery/live'))).toBe(false);
 expect(screen.getByRole('button',{name:/start discovery|démarrer discovery/i})).toBeDisabled();
});
