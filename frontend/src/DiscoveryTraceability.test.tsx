import {it,expect,vi,afterEach} from 'vitest';
import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import {LocaleProvider,localeKey} from './i18n';
import DiscoveryReal,{report} from './components/DiscoveryReal';
import {parseDiscoveryResponse} from './discoveryApi';
const capability={schema:'fortress.discovery-capability/1',lab:true,live:true};
const payload={schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'http_refused',requests:1,bytes:0,pages:[{id:'page-1',route:'page-1',depth:0,status:403,state:'access_denied',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null}],relations:[],resources:[],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion']};
afterEach(()=>{cleanup();localStorage.clear();vi.restoreAllMocks();});
it.each(['fr','en'] as const)('attaches launch trace to the live result and clears it on target change (%s)',async locale=>{
 localStorage.setItem(localeKey,locale);vi.spyOn(crypto,'randomUUID').mockReturnValue('12345678-1234-4123-8123-123456789abc');
 vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?capability:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);const input=screen.getByLabelText(/discovery https origin|origine https discovery/i);fireEvent.change(input,{target:{value:'https://example.invalid'}});fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
 const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;
 expect(html).toContain('12345678-1234-4123-8123-123456789abc');expect(html).toContain('https://example.invalid/');expect(html).toContain('2026-11-12T12:00:00Z');expect(html).toMatch(/GET/);expect(html).toMatch(/version du moteur : non fournie|engine version: not provided/i);expect(html).toMatch(/budget/i);expect(JSON.stringify(localStorage)).not.toContain('12345678-1234-4123-8123-123456789abc');
 fireEvent.change(input,{target:{value:'https://other.invalid'}});expect(screen.queryByTitle(/discovery report preview|aperçu du rapport discovery/i)).not.toBeInTheDocument();
});
it.each(['fr','en'] as const)('rejects hostile trace values and keeps history unmodified (%s)',locale=>{
 const data=parseDiscoveryResponse(payload,'live');const budgets={pages:5,requests:10,depth:1,interval:1,page_bytes:524288,total_bytes:3145728,seconds:120};
 for(const origin of ['https://example.invalid/private','https://user:secret@example.invalid/','https://example.invalid/?secret=x','https://example.invalid/#x','https://example.invalid/<script>']){
  const html=report(data,locale,'worker',{id:'12345678-1234-4123-8123-123456789abc',origin,budgets});expect(html).not.toContain(origin);expect(html).not.toContain('12345678-1234-4123-8123-123456789abc');expect(html).not.toContain('<script>');
 }
 const historical=report(data,locale,'historical',{id:'12345678-1234-4123-8123-123456789abc',origin:'https://example.invalid/',budgets});expect(historical).not.toContain('12345678-1234-4123-8123-123456789abc');expect(historical).not.toContain('https://example.invalid/');
});
it('marks the identifier unknown if secure UUID generation fails',async()=>{
 vi.spyOn(crypto,'randomUUID').mockImplementation(()=>{throw Error('unavailable');});
 vi.spyOn(globalThis,'fetch').mockImplementation(async u=>new Response(JSON.stringify(String(u).includes('/discovery/capability')?capability:String(u).includes('/mvp/capability')?{capability:'a'.repeat(32)}:payload)));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);fireEvent.change(screen.getByLabelText(/discovery https origin|origine https discovery/i),{target:{value:'https://example.invalid'}});fireEvent.click(screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i}));await screen.findByText(/live capability verified|capacité réelle vérifiée/i);fireEvent.click(screen.getByLabelText(/I confirm I am authorized|Je confirme être autorisé/i));fireEvent.click(screen.getByRole('button',{name:/start discovery|démarrer discovery/i}));
 const html=(await screen.findByTitle(/discovery report preview|aperçu du rapport discovery/i)).getAttribute('srcdoc')!;expect(html).toMatch(/(?:identifiant local de campagne: inconnu|local campaign identifier: unknown)/i);
});
