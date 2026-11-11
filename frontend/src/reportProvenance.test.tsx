import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import DigitalFortress from './views/DigitalFortress';
import {LocaleProvider,localeKey} from './i18n';
import {renderFortressReport} from './fortressReport';
import {parseObservation,renderLiveReport} from './liveObservation';

const fixture={mode:'fixture',scenario:'ok',route:'/',target:'https://standard-lab.invalid/',generated_at:'2026-11-05T12:00:00+00:00',http_status:200,failure_code:'none',tls:{},headers:{},cookies:{},findings:[],limits:['fixture_only']};
const live={mode:'live',target:'https://example.org/',observed_at:'2026-01-01T00:00:00Z',http_status:200,tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3',not_before:'Jan  1 00:00:00 2026 GMT',not_after:'Jan  1 00:00:00 2027 GMT'},headers:{hsts:'absent',csp:'absent',x_content_type_options:'absent',referrer_policy:'absent',permissions_policy:'absent'},failure_code:'none'};
const marker=(lang:'fr'|'en')=>lang==='fr'?'DÉMONSTRATION SYNTHÉTIQUE — AUCUNE OBSERVATION RÉELLE':'SYNTHETIC DEMONSTRATION — NO REAL OBSERVATION';

it.each(['fr','en'] as const)('marks the fixture in the actual preview and exported HTML (%s)',async lang=>{
 localStorage.setItem(localeKey,lang);
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(new Response(JSON.stringify({capability:'test-capability-secret-0123456789abcdef'}))).mockResolvedValueOnce(new Response(JSON.stringify(fixture)));
 const blobs:Blob[]=[];vi.stubGlobal('URL',Object.assign(URL,{createObjectURL:vi.fn((blob:Blob)=>{blobs.push(blob);return 'blob:test';}),revokeObjectURL:vi.fn()}));
 vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 fireEvent.click(screen.getByLabelText(/consent.*fixture|autorise.*fixture/i));fireEvent.click(screen.getByRole('button',{name:/run local fixture|lancer la fixture locale/i}));
 const html=(await screen.findByTitle(/report preview|aperçu du rapport/i)).getAttribute('srcdoc')!;
 expect(html).toContain(marker(lang));expect(html).toContain(lang==='fr'?'boucle locale':'loopback');
 fireEvent.click(screen.getByRole('button',{name:/télécharger le rapport html|download html report/i}));
 const exported=await new Promise<string>((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result));reader.onerror=reject;reader.readAsText(blobs[0]);});
 expect(exported).toBe(html);expect(exported).toContain(marker(lang));
 cleanup();vi.restoreAllMocks();vi.unstubAllGlobals();localStorage.removeItem(localeKey);
});

it.each(['fr','en'] as const)('does not label live or arbitrary data synthetic (%s)',lang=>{
 expect(renderLiveReport(parseObservation(live,live.target),lang)).not.toContain(marker(lang));
 expect(renderFortressReport({mode:'other',synthetic:true},lang)).not.toContain(marker(lang));
 expect(()=>parseObservation({...live,synthetic:true},live.target)).toThrow();
});

it.each(['fr','en'] as const)('does not discuss HSTS presence when absent or indeterminate (%s)',lang=>{
 for(const state of ['absent','indeterminate'] as const){const input=state==='absent'?live:{...live,http_status:null,failure_code:'timeout',tls:{certificate:'indeterminate',hostname:'indeterminate',protocol:null,not_before:null,not_after:null},headers:Object.fromEntries(Object.keys(live.headers).map(k=>[k,'indeterminate']))};const html=renderLiveReport(parseObservation(input,live.target),lang);const section=html.split('<section>')[6];expect(section).not.toContain(lang==='fr'?'La présence de HSTS ne démontre pas':'HSTS presence does not establish');expect(section).not.toContain('max-age=0');}
});
