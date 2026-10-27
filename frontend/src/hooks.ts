import { useCallback, useEffect, useRef, useState } from 'react';
export function useApi<T>(load:(signal:AbortSignal)=>Promise<T>, key:string) {
  const [state,setState] = useState<{data:T|null;error:Error|null;loading:boolean}>({data:null,error:null,loading:true});
  const generation=useRef(0),request=useRef<AbortController|null>(null);
  // Abort is best-effort: generations also reject transports that ignore it.
  const invalidate=useCallback(()=>{
    generation.current++;request.current?.abort();request.current=null;
    setState({data:null,error:null,loading:false});
  },[]);
  useEffect(() => {
    const controller = new AbortController(); const current=++generation.current;
    request.current=controller;
    setState({data:null,error:null,loading:true});
    load(controller.signal).then(data => {if(current===generation.current) setState({data,error:null,loading:false});})
      .catch(error => {if(current===generation.current && error?.name !== 'AbortError') setState({data:null,error:error instanceof Error ? error : new Error(String(error)),loading:false});});
    return () => {if(current===generation.current)generation.current++;controller.abort();};
  },[key]);
  return {...state,invalidate};
}
export function useHash() {
 const read = () => {const hash=window.location.hash.slice(1) || 'overview';try {return decodeURI(hash);} catch {return hash;}};
 const [route,setRoute] = useState(read);
 useEffect(()=>{const update=()=>setRoute(read());window.addEventListener('hashchange',update);return()=>window.removeEventListener('hashchange',update);},[]);
 return [route,(next:string)=>{window.location.hash=next;setRoute(next);}] as const;
}
