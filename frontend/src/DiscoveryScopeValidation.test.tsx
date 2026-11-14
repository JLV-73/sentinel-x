import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import {LocaleProvider} from './i18n';
import DiscoveryReal from './components/DiscoveryReal';
afterEach(()=>{cleanup();vi.restoreAllMocks();localStorage.clear();});
it('disables live start for routes rejected by the backend and allows valid scope',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({schema:'fortress.discovery-capability/1',lab:true,live:true})));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.org'}});
 fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));
 await screen.findByText(/live capability verified|capacité réelle vérifiée/i);
 const input=screen.getByLabelText(/discovery https origin|origine https discovery/i);
 const consent=screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i);
 const start=screen.getByRole('button',{name:/start discovery|démarrer discovery/i});
 fireEvent.click(consent);expect(start).toBeEnabled();
 for(const target of ['https://example.org?','https://example.org?x=1','https://example.org#',' https://example.org','https://example.org/products','https://example.org/products/..','https://example.org/%2e%2e','http://example.org','https://u:p@example.org','https://user@example.org']){
  fireEvent.change(input,{target:{value:target}});expect(consent).not.toBeChecked();fireEvent.click(consent);expect(start,target).toBeDisabled();fireEvent.click(start);
 }
 expect(fetcher.mock.calls.some(([url])=>String(url).endsWith('/discovery/live'))).toBe(false);
 fireEvent.change(input,{target:{value:'https://example.org/'}});fireEvent.click(consent);expect(start).toBeEnabled();
 fireEvent.change(input,{target:{value:'https://example.org'}});expect(start).toBeDisabled();fireEvent.click(consent);expect(start).toBeEnabled();
});
