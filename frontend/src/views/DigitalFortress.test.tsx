import {render,screen,fireEvent,waitFor,act} from '@testing-library/react';
import {beforeEach,describe,it,expect,vi} from 'vitest';
import {LocaleProvider,LanguageSwitch} from '../i18n';
import DigitalFortress from './DigitalFortress';
import {api} from '../api';
vi.mock('../api',()=>({api:{fortress:vi.fn()}}));
beforeEach(()=>{localStorage.setItem('sentinel-x.locale','en');vi.clearAllMocks()});
describe('Digital Fortress',()=>{
 it('starts empty and requires explicit consent before a manual request',async()=>{
  vi.mocked(api.fortress).mockResolvedValue({audit_id:'synthetic',mode:'standard',started_at:'now',finished_at:'now',scope:{origin:'https://example.test',paths:['/']},requests_used:1,complete:true,findings:[],limitations:[]});
  render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
  expect(screen.getByLabelText('Primary URL')).toHaveValue('');
  expect(screen.getByLabelText(/I confirm/)).not.toBeChecked();
  expect(api.fortress).not.toHaveBeenCalled();
  expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'}});
  fireEvent.click(screen.getByLabelText(/I confirm/));
  fireEvent.click(screen.getByRole('button',{name:'Start audit'}));
  await waitFor(()=>expect(api.fortress).toHaveBeenCalledWith({target:'https://example.test/',additional_urls:[],level:'standard',authorized:true,parameters:[]},expect.any(AbortSignal)));
 });
 it('preserves routes across language changes and strips query input',()=>{
  render(<LocaleProvider><LanguageSwitch/><DigitalFortress/></LocaleProvider>);
  fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/path'}});
  fireEvent.click(screen.getByRole('button',{name:'Add route'}));fireEvent.change(screen.getByLabelText('Additional URL 1'),{target:{value:'https://example.test/other'}});
  fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(screen.getByLabelText('URL principale')).toHaveValue('https://example.test/path');expect(screen.getByLabelText('URL supplémentaire 1')).toHaveValue('https://example.test/other');
  fireEvent.change(screen.getByLabelText('URL principale'),{target:{value:'https://example.test/path?token=secret'}});expect(screen.getByLabelText('URL principale')).not.toHaveValue(expect.stringContaining('secret'));expect(screen.getByRole('button',{name:'Lancer l’audit'})).toBeDisabled();expect(api.fortress).not.toHaveBeenCalled();
 });
 it('rejects foreign origins and sends only explicitly selected deep probes',async()=>{
  vi.mocked(api.fortress).mockResolvedValue({audit_id:'synthetic',mode:'deep',started_at:'now',finished_at:'now',scope:{origin:'https://example.test',paths:['/']},requests_used:1,complete:true,findings:[],limitations:[]});
  render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
  fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'}});fireEvent.click(screen.getByRole('button',{name:'Add route'}));
  fireEvent.change(screen.getByLabelText('Additional URL 1'),{target:{value:'https://other.test/'}});fireEvent.click(screen.getByLabelText(/I confirm/));expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Additional URL 1'),{target:{value:'https://example.test/route'}});fireEvent.change(screen.getByLabelText('Audit level'),{target:{value:'deep'}});fireEvent.click(screen.getByRole('button',{name:'Add parameter'}));
  fireEvent.change(screen.getByLabelText('Parameter route'),{target:{value:'https://example.test/route'}});fireEvent.change(screen.getByLabelText('Parameter name'),{target:{value:'next'}});fireEvent.change(screen.getByLabelText('Probe type'),{target:{value:'redirect'}});fireEvent.click(screen.getByLabelText(/I confirm/));fireEvent.click(screen.getByRole('button',{name:'Start audit'}));
  await waitFor(()=>expect(api.fortress).toHaveBeenCalledWith({target:'https://example.test/',additional_urls:['https://example.test/route'],level:'deep',authorized:true,parameters:[{url:'https://example.test/route',name:'next',kind:'redirect'}]},expect.any(AbortSignal)));
 });
});

it('invalidates an in-flight result when scope changes',async()=>{
 let resolve!: (v:any)=>void; vi.mocked(api.fortress).mockReturnValue(new Promise(r=>{resolve=r}));
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'}});
 fireEvent.click(screen.getByLabelText(/I confirm/)); fireEvent.click(screen.getByRole('button',{name:'Start audit'}));
 fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/changed'}});
 await act(async()=>resolve({audit_id:'x',mode:'standard',started_at:'now',finished_at:'now',scope:{origin:'https://example.test',paths:['/']},requests_used:1,complete:true,findings:[],limitations:[]}));
 expect(screen.queryByRole('button',{name:/Download/})).not.toBeInTheDocument();
 await new Promise(r=>setTimeout(r,20)); expect(screen.queryByText('https://example.test')).not.toBeInTheDocument();
});

it('removes displayed and downloadable results when consent or inputs change',async()=>{
 vi.mocked(api.fortress).mockResolvedValue({audit_id:'x',mode:'standard',started_at:'now',finished_at:'now',scope:{origin:'https://example.test',paths:['/']},requests_used:1,complete:true,findings:[],limitations:[]});
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'}});fireEvent.click(screen.getByLabelText(/I confirm/));fireEvent.click(screen.getByRole('button',{name:'Start audit'}));
 await screen.findByRole('button',{name:/Download/}); fireEvent.click(screen.getByLabelText(/I confirm/)); expect(screen.queryByRole('button',{name:/Download/})).not.toBeInTheDocument();
});
it('never renders server free text and localizes known classifications',async()=>{
 const secret='SENTINEL_SECRET'; vi.mocked(api.fortress).mockResolvedValue({audit_id:secret,mode:'standard',started_at:secret,finished_at:secret,scope:{origin:'https://x.test/#'+secret,paths:['/api_key='+secret]},requests_used:1,complete:true,findings:[{id:'hsts',status:'conformant',severity:'info',reason:'Bearer '+secret,evidence:'Cookie: '+secret,limitations:secret,preconditions:secret,recommendation:secret,reference:secret,method:'GET',route:secret,date:secret}],limitations:[secret]});
 const {container}=render(<LocaleProvider><LanguageSwitch/><DigitalFortress/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'}});fireEvent.click(screen.getByLabelText(/I confirm/));fireEvent.click(screen.getByRole('button',{name:'Start audit'})); await screen.findByText(/hsts/);
 expect(container.textContent).not.toContain(secret); expect(container.textContent).toContain('Conformant');expect(container.textContent).toContain('Informational');fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(container.textContent).toContain('Conforme');expect(container.textContent).toContain('Information');
});

it('rejects excessively long targets and credential-like parameter names',()=>{
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'+ 'a'.repeat(2048)}});fireEvent.click(screen.getByLabelText(/I confirm/));expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();
 fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'}});fireEvent.change(screen.getByLabelText('Audit level'),{target:{value:'deep'}});fireEvent.click(screen.getByRole('button',{name:'Add parameter'}));fireEvent.change(screen.getByLabelText('Parameter name'),{target:{value:'api_key'}});fireEvent.click(screen.getByLabelText(/I confirm/));expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();
});
