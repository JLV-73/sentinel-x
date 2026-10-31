import {render,screen,fireEvent,waitFor,act} from '@testing-library/react';
import {beforeEach,describe,it,expect,vi} from 'vitest';
import {LocaleProvider,LanguageSwitch} from '../i18n';
import DigitalFortress from './DigitalFortress';
import {api} from '../api';
vi.mock('../api',()=>({api:{fortress:vi.fn()}}));
const result={audit_id:'x',mode:'standard',started_at:'now',finished_at:'now',scope:{origin:'https://example.test',paths:['/']},requests_used:1,complete:true,findings:[],limitations:[]};
beforeEach(()=>{localStorage.setItem('sentinel-x.locale','en');vi.clearAllMocks()});
function setup(){return render(<LocaleProvider><LanguageSwitch/><DigitalFortress/></LocaleProvider>)}
function target(){fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'}})}
function consent(n=1){for(let i=1;i<=n;i++)fireEvent.click(screen.getByLabelText(`Safe GET for route ${i}`));fireEvent.click(screen.getByLabelText(/I confirm owner/))}
function start(){fireEvent.click(screen.getByRole('button',{name:'Start audit'}))}
describe('Digital Fortress',()=>{
 it('starts empty, unconsented and cannot issue an audit',()=>{
  setup();
  expect(screen.getByLabelText('Primary URL')).toHaveValue('');
  expect(screen.getByLabelText(/I confirm owner/)).not.toBeChecked();
  expect(screen.getByLabelText('Safe GET for route 1')).not.toBeChecked();
  expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();
  expect(api.fortress).not.toHaveBeenCalled();
 });
 it('preserves both routes when switching languages and strips query secrets in French',()=>{
  setup();fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/path'}});
  fireEvent.click(screen.getByRole('button',{name:'Add route'}));
  fireEvent.change(screen.getByLabelText('Additional URL 1'),{target:{value:'https://example.test/other'}});
  fireEvent.click(screen.getByRole('button',{name:'Français'}));
  expect(screen.getByLabelText('URL principale')).toHaveValue('https://example.test/path');
  expect(screen.getByLabelText('URL supplémentaire 1')).toHaveValue('https://example.test/other');
  fireEvent.change(screen.getByLabelText('URL principale'),{target:{value:'https://example.test/path?token=secret'}});
  expect(screen.getByLabelText('URL principale')).toHaveValue('https://example.test/path');
  expect(screen.getByRole('button',{name:'Lancer l’audit'})).toBeDisabled();
  expect(api.fortress).not.toHaveBeenCalled();
 });
 it('removes displayed findings and download on owner consent withdrawal',async()=>{
  vi.mocked(api.fortress).mockResolvedValue({...result,findings:[{id:'hsts',status:'conformant',severity:'info',reason:'',evidence:'',limitations:'',preconditions:'',recommendation:'',reference:'',method:'GET',route:'/',date:''}]});
  setup();target();consent();start();
  await screen.findByText(/hsts/);expect(screen.getByRole('button',{name:/Download/})).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText(/I confirm owner/));
  expect(screen.queryByText(/hsts/)).not.toBeInTheDocument();
  expect(screen.queryByRole('button',{name:/Download/})).not.toBeInTheDocument();
  expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();
 });
 it('requires safe GET confirmation for each exact route',()=>{
  setup();target();fireEvent.click(screen.getByLabelText(/I confirm owner/));expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();expect(screen.getByLabelText('Safe GET for route 1')).not.toBeChecked();
 });
 it('sends exact standard DTO only after each route and owner consent',async()=>{
  vi.mocked(api.fortress).mockResolvedValue(result);setup();expect(api.fortress).not.toHaveBeenCalled();target();fireEvent.click(screen.getByRole('button',{name:'Add route'}));fireEvent.change(screen.getByLabelText('Additional URL 1'),{target:{value:'https://example.test/two'}});
  expect(screen.getByLabelText('Method (GET only) 1')).toBeDisabled();expect(screen.getByLabelText('Method (GET only) 1')).toHaveValue('GET');expect(screen.getByLabelText('Method (GET only) 2')).toHaveValue('GET');
  fireEvent.click(screen.getByLabelText('Safe GET for route 1'));fireEvent.click(screen.getByLabelText(/I confirm owner/));expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();fireEvent.click(screen.getByLabelText('Safe GET for route 2'));start();
  await waitFor(()=>expect(api.fortress).toHaveBeenCalledWith({level:'standard',authorized:true,routes:[{url:'https://example.test/',safe_use_confirmed:true,methods:['GET'],cors_get:false,parameters:[]},{url:'https://example.test/two',safe_use_confirmed:true,methods:['GET'],cors_get:false,parameters:[]}]},expect.any(AbortSignal)));
 });
 it('disables advanced in English and French without losing scope',()=>{setup();target();expect(screen.getByLabelText('Audit level')).toBeDisabled();expect(screen.getByRole('option',{name:'Deep / advanced: unavailable'})).toBeDisabled();fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(screen.getByLabelText('URL principale')).toHaveValue('https://example.test/');expect(screen.getByLabelText('Niveau d’audit')).toBeDisabled();expect(screen.getByRole('option',{name:'Approfondi / avancé : indisponible'})).toBeDisabled();expect(screen.queryByRole('button',{name:'Ajouter un paramètre'})).not.toBeInTheDocument();});
 it('rejects other origins, query input and more than four routes',()=>{setup();target();fireEvent.click(screen.getByRole('button',{name:'Add route'}));fireEvent.change(screen.getByLabelText('Additional URL 1'),{target:{value:'https://other.test/'}});consent(2);expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/?secret=abc'}});expect(screen.getByLabelText('Primary URL')).toHaveValue('https://example.test/');expect(screen.getByLabelText(/I confirm owner/)).not.toBeChecked();expect(screen.getByLabelText('Safe GET for route 1')).not.toBeChecked();fireEvent.click(screen.getByRole('button',{name:'Add route'}));fireEvent.click(screen.getByRole('button',{name:'Add route'}));expect(screen.queryByRole('button',{name:'Add route'})).not.toBeInTheDocument();expect(api.fortress).not.toHaveBeenCalled();});
 it('invalidates a running response when a consent changes',async()=>{let resolve!: (v:typeof result)=>void;vi.mocked(api.fortress).mockReturnValue(new Promise(r=>{resolve=r}));setup();target();consent();start();const signal=vi.mocked(api.fortress).mock.calls[0][1]!;fireEvent.click(screen.getByLabelText('Safe GET for route 1'));expect(signal.aborted).toBe(true);await act(async()=>resolve(result));expect(screen.queryByRole('button',{name:/Download/})).not.toBeInTheDocument();});
 it('ignores a late response after a URL edit',async()=>{let resolve!: (v:typeof result)=>void;vi.mocked(api.fortress).mockReturnValue(new Promise(r=>{resolve=r}));setup();target();consent();start();const signal=vi.mocked(api.fortress).mock.calls[0][1]!;fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/changed'}});expect(signal.aborted).toBe(true);await act(async()=>resolve({...result,findings:[{id:'hsts',status:'conformant',severity:'info'}]} as typeof result));expect(screen.queryByRole('button',{name:/Download/})).not.toBeInTheDocument();expect(screen.queryByText(/hsts/)).not.toBeInTheDocument();expect(screen.queryByText('https://example.test')).not.toBeInTheDocument();expect(screen.getByLabelText(/I confirm owner/)).not.toBeChecked();});
 it('rejects excessively long and credential-bearing URLs',()=>{setup();fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/'+ 'a'.repeat(2048)}});consent();expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://user:secret@example.test/'}});consent();expect(screen.getByRole('button',{name:'Start audit'})).toBeDisabled();expect(api.fortress).not.toHaveBeenCalled();});
 it('clears old result and all consents on scope edits',async()=>{vi.mocked(api.fortress).mockResolvedValue(result);setup();target();consent();start();await screen.findByRole('button',{name:/Download/});fireEvent.change(screen.getByLabelText('Primary URL'),{target:{value:'https://example.test/new'}});expect(screen.queryByRole('button',{name:/Download/})).not.toBeInTheDocument();expect(screen.getByLabelText(/I confirm owner/)).not.toBeChecked();expect(screen.getByLabelText('Safe GET for route 1')).not.toBeChecked();});
 it('shows 503 disabled status without displaying server text',async()=>{vi.mocked(api.fortress).mockRejectedValue({status:503,detail:'SECRET'});const {container}=setup();target();consent();start();expect(await screen.findByRole('alert')).toHaveTextContent('Audit disabled until safety is verified (HTTP 503).');expect(container.textContent).not.toContain('SECRET');fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(screen.getByRole('alert')).toHaveTextContent('Audit désactivé');});
 it('never renders server free text and localizes classifications',async()=>{const secret='SENTINEL_SECRET';vi.mocked(api.fortress).mockResolvedValue({...result,audit_id:secret,started_at:secret,finished_at:secret,scope:{origin:'https://x.test/#'+secret,paths:['/api_key='+secret]},limitations:[secret],findings:[{id:'hsts',status:'conformant',severity:'info',reason:'Bearer '+secret,evidence:'Cookie: '+secret,limitations:secret,preconditions:secret,recommendation:secret,reference:secret,method:'GET',route:secret,date:secret}]});const {container}=setup();target();consent();start();await screen.findByText(/hsts/);expect(container.textContent).not.toContain(secret);expect(container.textContent).toContain('Conformant');expect(container.textContent).toContain('Informational');fireEvent.click(screen.getByRole('button',{name:'Français'}));expect(container.textContent).toContain('Conforme');expect(container.textContent).toContain('Information');expect(container.textContent).not.toContain(secret);});
});
