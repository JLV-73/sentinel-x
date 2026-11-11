import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import LiveObservation from './components/LiveObservation';
import {LocaleProvider,localeKey} from './i18n';
const result={mode:'live',target:'https://example.org/',observed_at:'2026-01-01T00:00:00Z',http_status:200,tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3',not_before:'Jan  1 00:00:00 2026 GMT',not_after:'Jan  1 00:00:00 2027 GMT'},headers:{hsts:'absent',csp:'absent',x_content_type_options:'absent',referrer_policy:'absent',permissions_policy:'absent'},failure_code:'none'};
afterEach(()=>{cleanup();vi.restoreAllMocks();window.localStorage.removeItem(localeKey);});
it.each(['fr','en'] as const)('uses identical %s HTML for React preview and export',async locale=>{
 window.localStorage.setItem(localeKey,locale);
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify({capability:'a'.repeat(32)}),{status:200})).mockResolvedValueOnce(new Response(JSON.stringify(result),{status:200}));
 let blob:Blob|undefined;vi.stubGlobal('URL',Object.assign(URL,{createObjectURL:(b:Blob)=>{blob=b;return 'blob:test';},revokeObjectURL:()=>{}}));vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
 render(<LocaleProvider><LiveObservation/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText(/URL HTTPS/i),{target:{value:'https://example.org/private?secret=1'}});fireEvent.click(screen.getByLabelText(/autorisé à observer|authorized to observe/i));fireEvent.click(screen.getByRole('button',{name:/observer le site|observe site/i}));
 const frame=await screen.findByTitle(/aperçu de l’observation|observation preview/i);const html=frame.getAttribute('srcdoc');expect(frame).toHaveAttribute('sandbox','');expect(html).toContain('<section>');expect(html).not.toContain('secret=1');
 fireEvent.click(screen.getByRole('button',{name:/télécharger.*observation|download.*observation/i}));expect(blob).toBeDefined();
 const text=await new Promise<string>((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result));reader.onerror=reject;reader.readAsText(blob!);});expect(text).toBe(html);
});
