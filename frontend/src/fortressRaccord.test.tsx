import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import DigitalFortress from './views/DigitalFortress';
import {LocaleProvider} from './i18n';
import {renderFortressReport} from './fortressReport';

it('bootstraps capability and posts only consent and scenario without exposing it',async()=>{
 const token='test-capability-secret-0123456789abcdef';
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce({ok:true,json:async()=>({capability:token})} as Response).mockResolvedValueOnce({ok:true,json:async()=>({mode:'fixture',scenario:'ok'})} as Response);
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText(/URL HTTPS/i),{target:{value:'https://private.example/secret'}});
 fireEvent.click(screen.getByLabelText(/consent.*fixture|autorise.*fixture/i));
 fireEvent.click(screen.getByRole('button',{name:/run local fixture|lancer la fixture locale/i}));
 await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(2));
 const [getUrl,getOptions]=fetcher.mock.calls[0], [postUrl,postOptions]=fetcher.mock.calls[1];
 expect(getUrl).toBe('http://127.0.0.1:8007/api/fortress/mvp/capability');
 expect(getOptions?.method).toBe('GET');expect(getOptions?.headers).toEqual({'X-Sentinel-Request':'sync'});
 expect(postUrl).toBe('http://127.0.0.1:8007/api/fortress/mvp/demo');
 expect(postOptions?.headers).toEqual({'X-Sentinel-Request':'sync','X-Sentinel-Capability':token,'Content-Type':'application/json'});
 expect(postOptions?.body).toBe(JSON.stringify({scenario:'ok',consent:true}));
 await screen.findByTitle(/report preview|aperçu du rapport/i);
 expect(document.documentElement.outerHTML).not.toContain(token);
 fetcher.mockRestore();
});
it('never treats forged claims as independently attested or exposes raw closed codes',()=>{
 const forged={mode:'fixture',route:'[redacted route]',scenario:'ok',generated_at:'2026-11-05T12:00:00+00:00',http_status:200,failure_code:'none',tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3',not_after:'Nov  5 12:00:00 2027 GMT'},headers:{},cookies:{count:0},findings:[{id:'tls_handshake',state:'observed',evidence:'fixture_tls_verified'}],limits:['no_active_tests']};
 for(const locale of ['fr','en'] as const){const html=renderFortressReport(forged,locale);expect(html).not.toMatch(/vérifié \(déclaré\)|verified \(reported\)|transmises par le backend|reported by the backend|fixture_tls_verified|not_performed/);expect(html).toMatch(/non attesté|not independently attested/i);expect(html).toContain('Nov  5 12:00:00 2027 GMT');}
});
