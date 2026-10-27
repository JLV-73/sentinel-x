import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import App from './App';
import {defaultResponse,json,vuln,record,status} from './test/fixtures';
import {initialLocale,translate,dictionaries,formatDate,formatNumber} from './i18n';
vi.mock('./components/Charts',()=>({TrendChart:()=>null,VendorChart:()=>null}));
beforeEach(()=>{localStorage.clear();window.location.hash='overview';vi.stubGlobal('fetch',vi.fn(async(url:string)=>defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it('switches language in place and persists the explicit preference',async()=>{
 localStorage.setItem('sentinel-x.locale','fr');render(<App/>);
 await screen.findByTestId('metric-total');
 fireEvent.click(screen.getByRole('button',{name:'English'}));
 expect(localStorage.getItem('sentinel-x.locale')).toBe('en');
 await waitFor(()=>expect(document.documentElement.lang).toBe('en'));
 expect(document.title).toBe('SENTINEL X · NIGHTFALL — Local threat monitor');
 expect(window.location.hash).toBe('#overview');
 expect(screen.getByRole('button',{name:'English'})).toHaveAttribute('aria-pressed','true');
 fireEvent.click(screen.getByRole('button',{name:'Français'}));
 expect(document.documentElement.lang).toBe('fr');
 expect(localStorage.getItem('sentinel-x.locale')).toBe('fr');
});
it('localizes every route without losing catalogue drafts, filters, pagination, detail JSON or history inspection',async()=>{
 localStorage.setItem('sentinel-x.locale','fr');window.location.hash='intelligence';
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>{
  if(url.includes('page_size=20'))return json({items:[vuln],total:41,page:Number(new URL(url,'http://localhost').searchParams.get('page')),page_size:20,pages:3});return defaultResponse(url);
 }));render(<App/>);
 const input=await screen.findByRole('searchbox');
 fireEvent.change(screen.getByLabelText('Éditeur exact'),{target:{value:'Microsoft'}});
 fireEvent.change(screen.getByLabelText('Ordre des ajouts'),{target:{value:'asc'}});
 fireEvent.change(screen.getByLabelText('Usage rançongiciel'),{target:{value:'Known'}});fireEvent.change(screen.getByLabelText('Ajouté depuis'),{target:{value:'2026-01-01'}});
 fireEvent.click(await screen.findByRole('button',{name:'Page suivante'}));
 await screen.findByText('Page 2 sur 3');
 fireEvent.change(input,{target:{value:'unsent draft'}});
 const calls=vi.mocked(fetch).mock.calls.length;fireEvent.click(screen.getByRole('button',{name:'English'}));
 expect(vi.mocked(fetch).mock.calls).toHaveLength(calls);expect(screen.getByLabelText('Ransomware use')).toHaveValue('Known');expect(screen.getByLabelText('Added since')).toHaveValue('2026-01-01');
 expect(screen.getByRole('heading',{name:/Vulnerability catalogue/})).toBeVisible();
 expect(screen.getByRole('searchbox',{name:'Search for a CVE, vendor or product'})).toBe(input);
 expect(input).toHaveValue('unsent draft');expect(screen.getByLabelText('Exact vendor')).toHaveValue('Microsoft');expect(screen.getByLabelText('Addition order')).toHaveValue('asc');
 expect(screen.getByText('Page 2 of 3')).toBeVisible();
 await waitFor(()=>expect(fetch).toHaveBeenCalledWith(expect.stringContaining('q=unsent+draft'),expect.anything()));
 fireEvent.click(await screen.findByRole('button',{name:`Open ${vuln.cveID}`}));
 expect(await screen.findByText('Official description')).toBeVisible();
 expect(screen.getByRole('heading',{level:1})).toHaveTextContent('CVE Inspector');expect(screen.getByRole('heading',{level:1})).toHaveTextContent(vuln.cveID);
 expect(screen.getByText(vuln.shortDescription)).toHaveAttribute('lang','en');
 expect(screen.getByText(vuln.requiredAction)).toHaveAttribute('lang','en');
 expect(screen.getByText(vuln.vulnerabilityName)).toHaveAttribute('lang','en');
 expect(screen.getAllByText('Official CISA text — English').length).toBeGreaterThan(0);
 fireEvent.click(screen.getByText('Original entry data'));const raw=document.querySelector('details')!;expect(raw.open).toBe(true);
 const hash=window.location.hash;fireEvent.click(screen.getByRole('button',{name:'Français'}));
 expect(window.location.hash).toBe(hash);expect(document.querySelector('details')).toBe(raw);expect(raw.open).toBe(true);
 expect(screen.getAllByText('Texte officiel CISA — anglais').length).toBeGreaterThan(0);
 fireEvent.click(screen.getByRole('button',{name:'Retour au catalogue'}));expect(await screen.findByRole('searchbox')).toHaveValue('unsent draft');
 window.location.hash='data';fireEvent(window,new HashChangeEvent('hashchange'));
 fireEvent.click(await screen.findByRole('button',{name:'Inspecter l’import 1'}));
 fireEvent.click(screen.getByRole('button',{name:'English'}));expect(screen.getByRole('heading',{name:'Import #1'})).toBeVisible();expect(screen.getByRole('button',{name:'Close details'})).toBeVisible();expect(screen.getByText('Verified integrity')).toBeVisible();
});
it.each([['fr-FR','fr'],['fr-CA','fr'],['en-GB','en'],['de-DE','en'],['FR-be','fr']])('uses primary browser language %s as %s',(language,locale)=>{
 vi.spyOn(navigator,'language','get').mockReturnValue(language);expect(initialLocale()).toBe(locale);
 localStorage.setItem('sentinel-x.locale','invalid');expect(initialLocale()).toBe(locale);
 localStorage.setItem('sentinel-x.locale','en');expect(initialLocale()).toBe('en');
 localStorage.setItem('sentinel-x.locale','fr');expect(initialLocale()).toBe('fr');
});
it('survives denied storage access and write quotas with in-memory preference',async()=>{
 vi.spyOn(navigator,'language','get').mockReturnValue('en-US');vi.spyOn(Storage.prototype,'getItem').mockImplementation(()=>{throw new DOMException('denied','SecurityError');});vi.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw new DOMException('full','QuotaExceededError');});
 render(<App/>);await screen.findByTestId('metric-total');expect(document.documentElement.lang).toBe('en');fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(document.documentElement.lang).toBe('fr');fireEvent.click(screen.getByRole('button',{name:'English'}));expect(document.documentElement.lang).toBe('en');
});

it('re-localizes a verified sync message even if language changed while the POST was pending',async()=>{
 localStorage.setItem('sentinel-x.locale','fr');window.location.hash='data';let posted=false;let release:(r:Response)=>void=()=>{};const next={...record,id:3};
 vi.stubGlobal('fetch',vi.fn((url:string,init?:RequestInit)=>{
  if(url==='/api/sync'&&init?.method==='POST'){posted=true;return new Promise<Response>(resolve=>{release=resolve;});}
  if(url==='/api/sync/status'&&posted)return Promise.resolve(json({...status,last_attempt:next,last_success:next,history:[next,record]}));return Promise.resolve(defaultResponse(url));
 }));render(<App/>);fireEvent.click(await screen.findByRole('button',{name:'Synchroniser maintenant'}));fireEvent.click(screen.getByRole('button',{name:'English'}));release(json(next));
 expect(await screen.findByText('Synchronisation verified')).toBeVisible();expect(screen.getByText('Import #3 confirmed by re-reading the local journal.')).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(screen.getByText('Synchronisation vérifiée')).toBeVisible();expect(screen.getByText('Import #3 confirmé par relecture du journal local.')).toBeVisible();
});
it('explains API failures in the current language and labels the original technical detail',async()=>{
 localStorage.setItem('sentinel-x.locale','en');vi.stubGlobal('fetch',vi.fn(async()=>json({detail:'Source officielle indisponible'},502)));render(<App/>);
 expect(await screen.findByText('Local service unavailable')).toBeVisible();expect(screen.getByText('The official source could not be imported. The last validated catalogue is retained.')).toBeVisible();expect(screen.getByText('Technical details (original, untranslated)')).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(screen.getByText('La source officielle n’a pas pu être importée. Le dernier catalogue validé est conservé.')).toBeVisible();
});

it('has complete matching keys and interpolation parameters in both dictionaries',()=>{
 expect(Object.keys(dictionaries.en).sort()).toEqual(Object.keys(dictionaries.fr).sort());
 for(const key of Object.keys(dictionaries.en) as (keyof typeof dictionaries.en)[]){expect(dictionaries.en[key].trim()).not.toBe('');expect(dictionaries.fr[key].trim()).not.toBe('');expect(dictionaries.en[key].match(/\{\w+\}/g)||[]).toEqual(dictionaries.fr[key].match(/\{\w+\}/g)||[]);}
 expect(translate('en','page',{page:2,pages:3})).toBe('Page 2 of 3');expect(translate('fr','syncConfirmed',{id:3})).toBe('Import #3 confirmé par relecture du journal local.');
});
it('formats dates and numbers by locale, keeping date-only UTC and timestamp instants intact',()=>{
 expect(formatNumber(12345,'en')).toBe('12,345');expect(formatNumber(12345,'fr')).toMatch(/12\s345/);
 expect(formatDate('2026-10-20',false,'en')).toBe('20 Oct 2026');expect(formatDate('2026-10-20',true,'en')).toBe('20 Oct 2026');expect(formatDate('2026-10-20',false,'fr')).toContain('20 oct. 2026');
 expect(formatDate('2026-10-20T23:30:00-07:00',true,'en')).toBe(formatDate('2026-10-21T06:30:00Z',true,'en'));
 expect(formatDate(null,false,'en')).toBe('Not available');expect(formatDate('invalid',false,'fr')).toBe('Date non disponible');
 const formatter=vi.spyOn(Intl,'DateTimeFormat');formatDate('2026-10-20',true,'en');expect(formatter).toHaveBeenLastCalledWith('en-GB',expect.objectContaining({timeZone:'UTC'}));formatDate('2026-10-20T12:00:00Z',true,'fr');expect(formatter.mock.calls.at(-1)?.[1]).not.toHaveProperty('timeZone');
});

it('keeps a stored preference across a fresh App mount regardless of browser language',async()=>{
 vi.spyOn(navigator,'language','get').mockReturnValue('fr-CA');localStorage.setItem('sentinel-x.locale','en');const mounted=render(<App/>);await screen.findByTestId('metric-total');expect(screen.getByRole('heading',{name:'Overview'})).toBeVisible();mounted.unmount();render(<App/>);await screen.findByTestId('metric-total');expect(document.documentElement.lang).toBe('en');expect(screen.getByTestId('language-en')).toHaveAttribute('aria-pressed','true');
});
it('handles a throwing localStorage getter, not just failing storage methods',async()=>{
 vi.spyOn(navigator,'language','get').mockReturnValue('fr-FR');vi.spyOn(window,'localStorage','get').mockImplementation(()=>{throw new DOMException('denied','SecurityError');});render(<App/>);await screen.findByTestId('metric-total');fireEvent.click(screen.getByTestId('language-en'));expect(document.documentElement.lang).toBe('en');expect(screen.getByRole('heading',{name:'Overview'})).toBeVisible();
});
it.each([false,true])('re-localizes failed sync and stale-status feedback (reread fails: %s)',async(stale)=>{
 localStorage.setItem('sentinel-x.locale','fr');window.location.hash='data';let posted=false;
 vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{if(url==='/api/sync'&&init?.method==='POST'){posted=true;return json({detail:'Source unavailable'},502);}if(posted&&stale&&url==='/api/sync/status')throw new TypeError('Failed to fetch');return defaultResponse(url);}));render(<App/>);fireEvent.click(await screen.findByRole('button',{name:'Synchroniser maintenant'}));await screen.findByText(stale?'Relecture du statut impossible. Le dernier état connu reste affiché.':'Le succès de cet import n’a pas pu être confirmé dans le journal local.');fireEvent.click(screen.getByTestId('language-en'));expect(screen.getByText(stale?'Unable to re-read status. The last known state remains displayed.':'The success of this import could not be confirmed in the local journal.')).toBeVisible();expect(screen.getByText('The official source could not be imported. The last validated catalogue is retained.')).toBeVisible();
});
it('renders English loading, empty and offline states without replacing real data',async()=>{
 localStorage.setItem('sentinel-x.locale','en');vi.stubGlobal('fetch',vi.fn(async(url:string)=>url==='/api/summary'?json({data_mode:'NO DATA',total:0}):defaultResponse(url)));const mounted=render(<App/>);expect(screen.getByText('Reading the local catalogue…')).toBeVisible();expect(await screen.findByText('No catalogue imported')).toBeVisible();expect(screen.getByText('NO DATA')).toHaveAttribute('data-mode','NO DATA');expect(screen.queryByTestId('metric-total')).not.toBeInTheDocument();fireEvent.click(screen.getByTestId('language-fr'));expect(screen.getByText('Aucune donnée')).toBeVisible();mounted.unmount();localStorage.setItem('sentinel-x.locale','en');vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));render(<App/>);expect(await screen.findByText('Local service unavailable')).toBeVisible();expect(screen.getByText('Connection to backend 127.0.0.1:8007 failed.')).toBeVisible();
});
