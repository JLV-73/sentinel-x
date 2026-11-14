import {afterEach,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render,screen} from '@testing-library/react';
import {LocaleProvider} from './i18n';
import DiscoveryReal from './components/DiscoveryReal';

afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks();localStorage.clear();});
it('times out an abort-ignoring capability fetch, discards late success and permits manual retry',async()=>{
 vi.useFakeTimers();
 let finish!:(value:Response)=>void;
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementationOnce(()=>new Promise<Response>(resolve=>{finish=resolve;})).mockResolvedValue(new Response(JSON.stringify({schema:'fortress.discovery-capability/1',lab:true,live:true})));
 render(<LocaleProvider><DiscoveryReal/></LocaleProvider>);
 const button=screen.getByRole('button',{name:/check discovery capability|vérifier la capacité discovery/i});
 fireEvent.click(button);expect(button).toBeDisabled();
 await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});
 expect(fetcher.mock.calls[0][1]?.signal?.aborted).toBe(true);
 expect(button).toBeEnabled();expect(screen.getByRole('alert')).toBeInTheDocument();
 expect(fetcher).toHaveBeenCalledTimes(1);
 await act(async()=>{finish(new Response(JSON.stringify({schema:'fortress.discovery-capability/1',lab:true,live:true})));});
 expect(screen.queryByText(/live capability verified|capacité réelle vérifiée/i)).not.toBeInTheDocument();
 fireEvent.click(button);
 await act(async()=>{await Promise.resolve();await Promise.resolve();});
 expect(fetcher).toHaveBeenCalledTimes(2);
 expect(screen.getByText(/live capability verified|capacité réelle vérifiée/i)).toBeInTheDocument();
});
