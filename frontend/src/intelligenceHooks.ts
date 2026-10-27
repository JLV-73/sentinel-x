import {useEffect,useRef,useState} from 'react';
import type {TranslationKey} from './i18n';
import type {IntelligenceAttempt} from './types';
// A POST response alone is never treated as confirmation. Read the exact local
// target back, including after a failed POST so retained data/errors are visible.
export function useVerifiedCollection<Result,Snapshot>({write,read,apply,verify,status,invalidate,cleanupDeferred}:{
 write:(signal:AbortSignal)=>Promise<Result>; read:(signal:AbortSignal)=>Promise<Snapshot>;
 apply:(value:Snapshot)=>void; verify:(result:Result,snapshot:Snapshot)=>boolean;
 status:(result:Result)=>IntelligenceAttempt['status']; invalidate:()=>void;
 cleanupDeferred?:(result:Result)=>boolean;
}) {
 const [busy,setBusy]=useState(false);
 const [message,setMessage]=useState<TranslationKey|null>(null);
 const [problem,setProblem]=useState<Error|null>(null);
 const [leaseDeferred,setLeaseDeferred]=useState(false);
 const active=useRef(true),guard=useRef(false),controller=useRef<AbortController|null>(null);
 useEffect(()=>{active.current=true;return()=>{active.current=false;controller.current?.abort();};},[]);
 const run=async()=>{
  if(guard.current)return;guard.current=true;invalidate();setBusy(true);setMessage(null);setProblem(null);setLeaseDeferred(false);
  const request=new AbortController();controller.current=request;
  let result:Result|undefined;let error:Error|null=null;
  try {result=await write(request.signal);}catch(e){error=e instanceof Error?e:new Error(String(e));}
  if(!active.current)return;
  if(result!==undefined)setLeaseDeferred(cleanupDeferred?.(result)===true);
  try {
   const snapshot=await read(request.signal);if(!active.current)return;invalidate();apply(snapshot);
   if(result!==undefined&&verify(result,snapshot))setMessage(status(result)==='success'?'intelVerified':status(result)==='partial'?'intelPartial':'intelFailed');
   else setMessage(error?'intelFailed':'intelUnconfirmed');
   setProblem(error);
  } catch(e){if(active.current){setMessage('intelUnconfirmed');setProblem(error??(e instanceof Error?e:new Error(String(e))));}}
  finally{guard.current=false;if(active.current)setBusy(false);}
 };
 return {busy,message,problem,leaseDeferred,run};
}
export function sameAttempt(result:IntelligenceAttempt|null,current:IntelligenceAttempt|null) {
 return !!result&&!!current&&result.source===current.source&&result.id===current.id&&result.status===current.status&&result.finished_at===current.finished_at&&(['requested','available','absent','failed'] as const).every(key=>result[key]===current[key]);
}
