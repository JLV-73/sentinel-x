import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import DigitalFortress from './views/DigitalFortress';
import {LocaleProvider} from './i18n';
const base={mode:'fixture',scenario:'ok',route:'[redacted route]',generated_at:'2026-11-05T12:00:00+00:00',http_status:200,failure_code:'none',tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3'},headers:{},cookies:{count:0,secure:0,httponly:0,samesite:0},findings:[],limits:['fixture_only']};
it('previews the renderer output and invalidates it on scenario changes',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce({ok:true,json:async()=>({capability:'test-capability-secret-0123456789abcdef'})} as Response).mockResolvedValueOnce({ok:true,json:async()=>base} as Response);
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 fireEvent.click(screen.getByLabelText(/consent.*fixture|autorise.*fixture/i));
 fireEvent.click(screen.getByRole('button',{name:/run local fixture|lancer la fixture locale/i}));
 const frame=await screen.findByTitle(/report preview|aperçu du rapport/i);
 expect(frame).toHaveAttribute('sandbox','');expect(frame.getAttribute('srcdoc')).toContain('200');
 fireEvent.change(screen.getByLabelText(/scenario|scénario/i),{target:{value:'forbidden'}});
 expect(screen.queryByTitle(/report preview|aperçu du rapport/i)).not.toBeInTheDocument();
 expect(screen.getByRole('button',{name:/run local fixture|lancer la fixture locale/i})).toBeDisabled();
});
it('rejects a backend result missing its scenario',async()=>{
 const {scenario:_,...missing}=base;const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce({ok:true,json:async()=>({capability:'test-capability-secret-0123456789abcdef'})} as Response).mockResolvedValueOnce({ok:true,json:async()=>missing} as Response);
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 fireEvent.click(screen.getByLabelText(/consent.*fixture|autorise.*fixture/i));fireEvent.click(screen.getByRole('button',{name:/run local fixture|lancer la fixture locale/i}));
 await waitFor(()=>expect(screen.getByRole('alert')).toHaveTextContent(/indeterminate|indéterminés/i));
 expect(fetcher).toHaveBeenCalledTimes(2);
 expect(screen.queryByTitle(/report preview|aperçu du rapport/i)).not.toBeInTheDocument();
});
