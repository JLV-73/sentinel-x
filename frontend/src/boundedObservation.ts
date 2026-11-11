// Bound the received bytes before UTF-8 decoding or parsing. Content-Length is
// only an early rejection hint: it may be absent, compressed, or dishonest.
const MAX_CHUNKS=4096;
const RECEPTION_MS=15_000;
export async function readBoundedJson(response:Response,maxBytes:number,signal?:AbortSignal):Promise<unknown>{
 if(!Number.isSafeInteger(maxBytes)||maxBytes<1||!response.body)throw new Error('invalid response');
 const reader=response.body.getReader();
 const data=new Uint8Array(maxBytes);
 let length=0,chunks=0,complete=false;
 const started=Date.now();
 let timer:ReturnType<typeof setTimeout>|undefined;
 let onAbort:(()=>void)|undefined;
 const interrupted=new Promise<never>((_,reject)=>{
  const fail=()=>reject(new Error('response interrupted'));
  onAbort=fail;
  signal?.addEventListener('abort',fail,{once:true});
  timer=setTimeout(fail,RECEPTION_MS);
 });
 try{
  const advertised=response.headers.get('content-length');
  if(advertised&&/^\d+$/.test(advertised)&&Number(advertised)>maxBytes)throw new Error('response too large');
  while(true){
   if(signal?.aborted||Date.now()-started>=RECEPTION_MS)throw new Error('response interrupted');
   const part=await Promise.race([reader.read(),interrupted]);
   if(signal?.aborted||Date.now()-started>=RECEPTION_MS)throw new Error('response interrupted');
   if(part.done){complete=true;break;}
   if(!ArrayBuffer.isView(part.value)||Object.prototype.toString.call(part.value)!=='[object Uint8Array]'||++chunks>MAX_CHUNKS||part.value.byteLength>maxBytes-length)throw new Error('response too large');
   data.set(part.value,length);length+=part.value.byteLength;
  }
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data.subarray(0,length))) as unknown;
 }finally{
  if(timer!==undefined)clearTimeout(timer);
  if(onAbort)signal?.removeEventListener('abort',onAbort);
  if(!complete){try{void reader.cancel().catch(()=>{});}catch{/* Preserve the original failure. */}}
  try{reader.releaseLock();}catch{/* A pending read may still be settling. */}
 }
}
