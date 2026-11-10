import {useEffect,useRef,useState} from 'react';
import {useI18n} from '../i18n';
import {parseObservation,renderLiveReport,validInput,type Observation} from '../liveObservation';
import {readBoundedJson} from '../boundedObservation';
export default function LiveObservation(){
 const {locale}=useI18n(),fr=locale==='fr';
 const [target,setTarget]=useState(''),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(false),[result,setResult]=useState<Observation|null>(null);
 const sequence=useRef(0),abort=useRef<AbortController|null>(null);
 const invalidate=()=>{sequence.current++;abort.current?.abort();abort.current=null;setBusy(false);setError(false);setResult(null);};
 useEffect(()=>()=>{sequence.current++;abort.current?.abort();},[]);
 const run=async()=>{
  if(!consent||busy||!validInput(target))return;
  const id=++sequence.current,controller=new AbortController();abort.current=controller;setBusy(true);setError(false);setResult(null);
  const timer=setTimeout(()=>{if(sequence.current===id){sequence.current++;abort.current=null;setBusy(false);setError(true);controller.abort();}},15_000);
  const options={credentials:'omit' as const,redirect:'error' as const,cache:'no-store' as const,signal:controller.signal};
  try{
   const boot=await fetch('http://127.0.0.1:8007/api/fortress/mvp/capability',{...options,method:'GET',headers:{'X-Sentinel-Request':'sync'}});
   if(!boot.ok){void boot.body?.cancel().catch(()=>{});throw new Error();}const token:unknown=await readBoundedJson(boot,1024,controller.signal);
   if(!token||typeof token!=='object'||typeof (token as {capability?:unknown}).capability!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test((token as {capability:string}).capability)||controller.signal.aborted||sequence.current!==id)throw new Error();
   const response=await fetch('http://127.0.0.1:8007/api/fortress/audit',{...options,method:'POST',headers:{'X-Sentinel-Request':'sync','X-Sentinel-Capability':(token as {capability:string}).capability,'Content-Type':'application/json'},body:JSON.stringify({url:target,consent:true})});
   if(!response.ok){void response.body?.cancel().catch(()=>{});throw new Error();}const parsed=parseObservation(await readBoundedJson(response,256*1024,controller.signal),target);
   if(sequence.current===id&&!controller.signal.aborted)setResult(parsed);
  }catch{if(sequence.current===id&&!controller.signal.aborted)setError(true);controller.abort();}finally{clearTimeout(timer);if(sequence.current===id){setBusy(false);abort.current=null;}}
 };
 const html=result?renderLiveReport(result,locale):'';
 const download=()=>{if(!html)return;const url=URL.createObjectURL(new Blob([html],{type:'text/html;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=`digital-fortress-observation-${locale}.html`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 return <section className="panel fortress-panel"><h2>{fr?'Observation HTTPS':'HTTPS observation'}</h2><p>{fr?'Tentative d’observation HTTPS HEAD ; redirections non suivies. Le chemin et les paramètres sont transmis au service local pour l’observation mais masqués dans le résultat. Aucun scan de vulnérabilités. La présence d’un en-tête ne prouve pas sa conformité.':'HTTPS HEAD observation attempt; redirects are not followed. Path and query are sent to the local service for observation but masked in the result. No vulnerability scan. Header presence does not establish compliance.'}</p><p>{fr?'Modifier ou fermer cette vue ne garantit pas l’annulation d’une requête déjà engagée.':'Changing or closing this view does not guarantee cancellation of an already started request.'}</p>
 <label className="fortress-label">URL HTTPS<input type="url" autoComplete="off" value={target} onChange={e=>{invalidate();setTarget(e.target.value);setConsent(false);}} placeholder="https://example.org"/></label>
 <label className="fortress-consent"><input type="checkbox" checked={consent} onChange={e=>{invalidate();setConsent(e.target.checked);}}/>{fr?'Je confirme être autorisé à observer ce site.':'I confirm I am authorized to observe this site.'}</label>
 <button type="button" className="button" disabled={!consent||busy||!validInput(target)} onClick={()=>void run()}>{busy?(fr?'Observation…':'Observing…'):(fr?'Observer le site':'Observe site')}</button>
 {error&&<p role="alert">{fr?'Observation indisponible ou réponse incompatible. Aucun résultat produit.':'Observation unavailable or incompatible response. No result produced.'}</p>}
 {result&&<div aria-live="polite"><h3>{fr?'Observation réelle':'Live observation'}</h3><p>{fr?'Rapport distinct fondé sur la tentative d’observation HTTPS HEAD ; aucun résultat de démonstration substitué.':'Separate report based on the HTTPS HEAD observation attempt; no demonstration result substituted.'}</p><button type="button" className="button" onClick={download}>{fr?'Télécharger l’observation HTML':'Download observation HTML'} · {locale.toUpperCase()}</button><iframe title={fr?'Aperçu de l’observation':'Observation preview'} className="fortress-preview" sandbox="" srcDoc={html}/></div>}
 </section>;
}
