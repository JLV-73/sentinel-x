import {act,renderHook,waitFor} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import {useApi} from './hooks';

function deferred<T>() {
 let resolve!:(value:T)=>void;let reject!:(error:Error)=>void;
 const promise=new Promise<T>((yes,no)=>{resolve=yes;reject=no;});
 return {promise,resolve,reject};
}

it.each(['resolve','reject'] as const)('rejects a cancelled resource generation that ignores AbortSignal (%s), without blocking later reads',async(outcome)=>{
 const old=deferred<string>(),next=deferred<string>();let oldSignal!:AbortSignal;
 const load=vi.fn((signal:AbortSignal)=>{if(load.mock.calls.length===1){oldSignal=signal;return old.promise;}return next.promise;});
 const {result,rerender}=renderHook(({key})=>useApi(load,key),{initialProps:{key:'initial'}});
 act(()=>result.current.invalidate());
 expect(oldSignal.aborted).toBe(true);expect(result.current.loading).toBe(false);
 rerender({key:'refresh'});expect(result.current.loading).toBe(true);
 await act(async()=>{if(outcome==='resolve')old.resolve('stale');else old.reject(new Error('stale failure'));});
 expect(result.current.data).toBeNull();expect(result.current.error).toBeNull();expect(result.current.loading).toBe(true);
 await act(async()=>next.resolve('fresh'));
 await waitFor(()=>expect(result.current.data).toBe('fresh'));
 expect(result.current.error).toBeNull();expect(result.current.loading).toBe(false);
});

it('invalidates previous keys and unmounted reads even when the transport ignores cancellation',async()=>{
 const old=deferred<string>(),current=deferred<string>(),last=deferred<string>();
 const signals:AbortSignal[]=[];
 const load=vi.fn((signal:AbortSignal)=>{signals.push(signal);return [old,current,last][signals.length-1].promise;});
 const {result,rerender,unmount}=renderHook(({key})=>useApi(load,key),{initialProps:{key:'old'}});
 rerender({key:'current'});expect(signals[0].aborted).toBe(true);
 await act(async()=>current.resolve('current'));
 await act(async()=>old.resolve('old'));
 expect(result.current.data).toBe('current');
 rerender({key:'last'});unmount();expect(signals[2].aborted).toBe(true);
 await act(async()=>last.reject(new Error('late unmounted failure')));
 expect(load).toHaveBeenCalledTimes(3);
});
