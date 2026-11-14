import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {LocaleProvider} from './i18n';
import DiscoveryReal from './components/DiscoveryReal';
it('requires explicit lab consent, capability and posts only the fixed lab payload',async()=>{
 const f=vi.spyOn(globalThis,'fetch').mockImplementation(async (url)=>String(url).endsWith('capability')?new Response(JSON.stringify({capability:'a'.repeat(32)})):new Response(JSON.stringify({schema:'fortress.discovery/1',provenance:'lab',complete:false,reason:'http_refused',requests:1,bytes:0,pages:[{id:'page-1',route:'page-1',depth:0,status:403,state:'access_denied',observed_at:null,findings:[],observations:null}],relations:[],resources:[],limits:[]})));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 const run=screen.getByRole('button',{name:/run discovery lab|lancer le laboratoire discovery/i});expect(run).toBeDisabled();
 fireEvent.click(screen.getByLabelText(/authorize the discovery laboratory|autorise le laboratoire discovery/i));fireEvent.click(run);
 await waitFor(()=>expect(f).toHaveBeenCalledTimes(2));expect(f.mock.calls[1][0]).toBe('http://127.0.0.1:8007/api/fortress/discovery/lab');expect(JSON.parse(String(f.mock.calls[1][1]?.body))).toEqual({authorized:true});
 const frame=await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i);expect(frame.getAttribute('srcdoc')).toContain('403');expect(frame.getAttribute('srcdoc')).not.toContain('SECRET');fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.org'}});expect(screen.queryByTitle(/discovery report preview|aperçu du rapport discovery/i)).not.toBeInTheDocument();f.mockRestore();
});
