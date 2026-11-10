import {afterEach,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import DigitalFortress from './views/DigitalFortress';
import LiveObservation from './components/LiveObservation';
import {LocaleProvider} from './i18n';

const token=()=>new Response(JSON.stringify({capability:'a'.repeat(32)}));
const start=(kind:'live'|'fixture')=>{
 render(<LocaleProvider>{kind==='live'?<LiveObservation/>:<DigitalFortress/>}</LocaleProvider>);
 if(kind==='live'){
  fireEvent.change(screen.getByLabelText(/URL HTTPS/i),{target:{value:'https://example.org/'}});
  fireEvent.click(screen.getByLabelText(/autorisé à observer|authorized to observe/i));
  fireEvent.click(screen.getByRole('button',{name:/observer le site|observe site/i}));
 }else{
  fireEvent.click(screen.getByLabelText(/consent.*fixture|autorise.*fixture/i));
  fireEvent.click(screen.getByRole('button',{name:/run local fixture|lancer la fixture locale/i}));
 }
};
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.useRealTimers();});
it.each(['live','fixture'] as const)('%s aborts stalled response headers and shows an error',async kind=>{
 vi.useFakeTimers();let signal:AbortSignal|undefined;
 vi.spyOn(globalThis,'fetch').mockImplementation((_url,options)=>new Promise((_resolve,reject)=>{
  signal=options?.signal as AbortSignal;signal.addEventListener('abort',()=>reject(new Error('aborted')));
 }));
 start(kind);await act(async()=>{await vi.advanceTimersByTimeAsync(15000);});
 expect(signal?.aborted).toBe(true);expect(screen.getByRole('alert')).toBeInTheDocument();
 expect(screen.queryByTitle(/observation preview|aperçu de l’observation|report preview|aperçu du rapport/i)).not.toBeInTheDocument();
});
it.each(['live','fixture'] as const)('%s releases a non-cooperative capability timeout and ignores its late response during retry',async kind=>{
 vi.useFakeTimers();let finishOld!:(r:Response)=>void,finishRetry!:(r:Response)=>void;let oldSignal:AbortSignal|undefined;
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementationOnce((_url,options)=>new Promise(resolve=>{oldSignal=options?.signal as AbortSignal;finishOld=resolve;})).mockImplementationOnce(()=>new Promise(resolve=>{finishRetry=resolve;}));
 start(kind);await act(async()=>{await vi.advanceTimersByTimeAsync(15000);});
 expect(oldSignal?.aborted).toBe(true);expect(fetcher).toHaveBeenCalledTimes(1);expect(screen.getByRole('alert')).toBeInTheDocument();
 const button=screen.getByRole('button',{name:kind==='live'?/observer le site|observe site|observation…|observing…/i:/run local fixture|lancer la fixture locale|exécution…|running…/i});expect(button).toBeEnabled();
 fireEvent.click(button);expect(fetcher).toHaveBeenCalledTimes(2);
 await act(async()=>{finishOld(token());});expect(fetcher).toHaveBeenCalledTimes(2);expect(button).toBeDisabled();expect(screen.queryByRole('alert')).not.toBeInTheDocument();
 expect(screen.queryByTitle(/observation preview|aperçu de l’observation|report preview|aperçu du rapport/i)).not.toBeInTheDocument();
 await act(async()=>{finishRetry(new Response(null,{status:503}));});expect(button).toBeEnabled();expect(screen.getByRole('alert')).toBeInTheDocument();
});
it.each(['live','fixture'] as const)('%s releases a non-cooperative POST timeout and ignores a late result during retry',async kind=>{
 vi.useFakeTimers();let finishOld!:(r:Response)=>void,finishRetry!:(r:Response)=>void;let oldSignal:AbortSignal|undefined;
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(token()).mockImplementationOnce((_url,options)=>new Promise(resolve=>{oldSignal=options?.signal as AbortSignal;finishOld=resolve;})).mockImplementationOnce(()=>new Promise(resolve=>{finishRetry=resolve;}));
 start(kind);await act(async()=>{await vi.advanceTimersByTimeAsync(15000);});
 expect(oldSignal?.aborted).toBe(true);expect(fetcher).toHaveBeenCalledTimes(2);expect(screen.getByRole('alert')).toBeInTheDocument();
 const button=screen.getByRole('button',{name:kind==='live'?/observer le site|observe site|observation…|observing…/i:/run local fixture|lancer la fixture locale|exécution…|running…/i});expect(button).toBeEnabled();
 fireEvent.click(button);expect(fetcher).toHaveBeenCalledTimes(3);
 await act(async()=>{finishOld(new Response(JSON.stringify({mode:'fixture',scenario:'ok'})));});expect(fetcher).toHaveBeenCalledTimes(3);expect(button).toBeDisabled();expect(screen.queryByRole('alert')).not.toBeInTheDocument();
 expect(screen.queryByTitle(/observation preview|aperçu de l’observation|report preview|aperçu du rapport/i)).not.toBeInTheDocument();
 await act(async()=>{finishRetry(new Response(null,{status:503}));});expect(button).toBeEnabled();expect(screen.getByRole('alert')).toBeInTheDocument();
});
it.each(['live','fixture'] as const)('%s cancels an unbounded non-OK response',async kind=>{
 let cancelled=false;let signal:AbortSignal|undefined;
 const stream=new ReadableStream<Uint8Array>({cancel(){cancelled=true;}});
 vi.spyOn(globalThis,'fetch').mockImplementation(async(_url,options)=>{signal=options?.signal as AbortSignal;return new Response(stream,{status:503});});
 start(kind);await screen.findByRole('alert');expect(signal?.aborted).toBe(true);await waitFor(()=>expect(cancelled).toBe(true));
});
it('rejects an oversized streamed fixture before parsing it',async()=>{
 let cancelled=false;
 const payload=new TextEncoder().encode('{"mode":"fixture","scenario":"ok","padding":"'+'x'.repeat(300000)+'"}');
 const stream=new ReadableStream<Uint8Array>({start(c){c.enqueue(payload);},cancel(){cancelled=true;}});
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(new Response(stream));
 start('fixture');await screen.findByRole('alert');expect(cancelled).toBe(true);
 expect(screen.queryByTitle(/report preview|aperçu du rapport/i)).not.toBeInTheDocument();
});
it.each(['live','fixture'] as const)('%s keeps one timeout across capability and POST headers',async kind=>{
 vi.useFakeTimers();let signal:AbortSignal|undefined;
 vi.spyOn(globalThis,'fetch').mockImplementationOnce(async()=>token()).mockImplementationOnce((_url,options)=>new Promise((_resolve,reject)=>{
  signal=options?.signal as AbortSignal;signal.addEventListener('abort',()=>reject(new Error('aborted')));
 }));
 start(kind);await act(async()=>{await vi.advanceTimersByTimeAsync(14999);});
 expect(signal).toBeDefined();expect(signal?.aborted).toBe(false);
 await act(async()=>{await vi.advanceTimersByTimeAsync(1);});expect(signal?.aborted).toBe(true);expect(screen.getByRole('alert')).toBeInTheDocument();
});
it.each(['live','fixture'] as const)('%s cancels a non-OK POST body',async kind=>{
 let cancelled=false;let signal:AbortSignal|undefined;
 const stream=new ReadableStream<Uint8Array>({cancel(){cancelled=true;}});
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(token()).mockImplementationOnce(async(_url,options)=>{signal=options?.signal as AbortSignal;return new Response(stream,{status:503});});
 start(kind);await screen.findByRole('alert');expect(signal?.aborted).toBe(true);await waitFor(()=>expect(cancelled).toBe(true));
});
it('rejects an oversized fixture capability before POST',async()=>{
 let cancelled=false;const stream=new ReadableStream<Uint8Array>({start(c){c.enqueue(new TextEncoder().encode(' '.repeat(1025)));},cancel(){cancelled=true;}});
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(stream));
 start('fixture');await screen.findByRole('alert');expect(cancelled).toBe(true);expect(fetcher).toHaveBeenCalledTimes(1);
});
it('ignores a late fixture result after the scenario changes',async()=>{
 let finish!:(r:Response)=>void;
 vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(token()).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
 start('fixture');await waitFor(()=>expect(finish).toBeDefined());
 fireEvent.change(screen.getByLabelText(/scenario|scénario/i),{target:{value:'forbidden'}});
 await act(async()=>{finish(new Response(JSON.stringify({mode:'fixture',scenario:'ok'})));});
 expect(screen.queryByTitle(/report preview|aperçu du rapport/i)).not.toBeInTheDocument();expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
