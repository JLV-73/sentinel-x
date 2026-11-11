import {afterEach,expect,it,vi} from 'vitest';
import {createElement} from 'react';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import LiveObservation from './components/LiveObservation';
import {LocaleProvider} from './i18n';
import {readBoundedJson} from './boundedObservation';

afterEach(()=>{cleanup();vi.restoreAllMocks();vi.useRealTimers();});
const bytes=(s:string)=>new TextEncoder().encode(s);
function response(chunks:Uint8Array[], headers:Record<string,string>={}) {
 let index=0;
 return new Response(new ReadableStream<Uint8Array>({pull(controller){if(index===chunks.length)controller.close();else controller.enqueue(chunks[index++]);}}),{headers});
}
it('decodes UTF-8 only after receiving a bounded multi-byte stream',async()=>{
 const data=bytes('{"message":"é🛡"}');
 await expect(readBoundedJson(response(Array.from(data,b=>new Uint8Array([b]))),data.length)).resolves.toEqual({message:'é🛡'});
});
it('rejects excess bytes despite a lying Content-Length and cancels the stream',async()=>{
 let cancelled=false;
 const stream=new ReadableStream<Uint8Array>({pull(c){c.enqueue(bytes('12345'));},cancel(){cancelled=true;}});
 await expect(readBoundedJson(new Response(stream,{headers:{'Content-Length':'1'}}),4)).rejects.toThrow();
 expect(cancelled).toBe(true);
});
it('rejects an advertised oversized body without reading it',async()=>{
 let cancelled=false;
 const stream=new ReadableStream<Uint8Array>({cancel(){cancelled=true;}});
 await expect(readBoundedJson(new Response(stream,{headers:{'Content-Length':'100'}}),4)).rejects.toThrow();
 expect(cancelled).toBe(true);
});
it('rejects missing bodies, invalid UTF-8 and malformed JSON',async()=>{
 await expect(readBoundedJson(new Response(null),16)).rejects.toThrow();
 await expect(readBoundedJson(response([new Uint8Array([0xff])]),16)).rejects.toThrow();
 await expect(readBoundedJson(response([bytes('{')]),16)).rejects.toThrow();
});
it('rejects excessively fragmented and infinite empty streams',async()=>{
 let cancelled=false;
 const stream=new ReadableStream<Uint8Array>({pull(c){c.enqueue(new Uint8Array());},cancel(){cancelled=true;}});
 await expect(readBoundedJson(new Response(stream),16)).rejects.toThrow();
 expect(cancelled).toBe(true);
});
it('rejects a reader failure without falling back to response.json',async()=>{
 const stream=new ReadableStream<Uint8Array>({pull(c){c.error(new Error('reader failure'));}});
 const r=new Response(stream);const fallback=vi.spyOn(r,'json');
 await expect(readBoundedJson(r,16)).rejects.toThrow();expect(fallback).not.toHaveBeenCalled();
});
it('rejects when stream cancellation itself fails',async()=>{
 const stream=new ReadableStream<Uint8Array>({pull(c){c.enqueue(bytes('12345'));},cancel(){throw new Error('cancel failed');}});
 await expect(readBoundedJson(new Response(stream),4)).rejects.toThrow();
});
it('rejects a locked reader',async()=>{
 const r=new Response(new ReadableStream<Uint8Array>());const lock=r.body!.getReader();
 await expect(readBoundedJson(r,16)).rejects.toThrow();
 lock.releaseLock();
});
it('rejects an aborted pending read and cancels its stream',async()=>{
 let cancelled=false;const abort=new AbortController();
 const stream=new ReadableStream<Uint8Array>({cancel(){cancelled=true;}});
 const pending=readBoundedJson(new Response(stream),16,abort.signal);abort.abort();
 await expect(pending).rejects.toThrow();expect(cancelled).toBe(true);
});
it('rejects a stalled stream within the reception deadline',async()=>{
 vi.useFakeTimers();let cancelled=false;
 const stream=new ReadableStream<Uint8Array>({cancel(){cancelled=true;}});
 const pending=readBoundedJson(new Response(stream),16);const assertion=expect(pending).rejects.toThrow();
 await vi.advanceTimersByTimeAsync(15_001);await assertion;expect(cancelled).toBe(true);
});
it('does not parse a malicious oversized JSON value',async()=>{
 const parse=vi.spyOn(JSON,'parse');
 await expect(readBoundedJson(response([bytes('{"payload":"'+ 'x'.repeat(100) +'"}')]),32)).rejects.toThrow();
 expect(parse).not.toHaveBeenCalled();
});

it.each(['capability','audit'])('rejects an oversized %s response in the live UI',async(stage)=>{
 const malicious=response([bytes(JSON.stringify({payload:'x'.repeat(256*1024+1)}))],{'Content-Length':'1'});
 const fetcher=vi.spyOn(globalThis,'fetch');
 if(stage==='audit')fetcher.mockResolvedValueOnce(new Response(JSON.stringify({capability:'a'.repeat(32)})));
 fetcher.mockResolvedValueOnce(malicious);
 render(createElement(LocaleProvider,null,createElement(LiveObservation)));
 fireEvent.change(screen.getByLabelText(/URL HTTPS/i),{target:{value:'https://example.org/'}});
 fireEvent.click(screen.getByLabelText(/autorisé à observer|authorized to observe/i));
 fireEvent.click(screen.getByRole('button',{name:/observer le site|observe site/i}));
 expect(await screen.findByRole('alert')).toHaveTextContent(/indisponible|unavailable/i);
 expect(fetcher).toHaveBeenCalledTimes(stage==='audit'?2:1);
 expect(screen.queryByTitle(/aperçu de l’observation|observation preview/i)).toBeNull();
});

it('rejects a pre-aborted signal without parsing or an unhandled rejection',async()=>{
 const abort=new AbortController();abort.abort();
 await expect(readBoundedJson(response([bytes('{}')]),16,abort.signal)).rejects.toThrow();
});
