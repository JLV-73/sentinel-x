import {useEffect,useRef,useState} from 'react';
import {useI18n} from '../i18n';
import {renderFortressReport} from '../fortressReport';
import {parseDiagnostic,MAX_IMPORT_BYTES} from '../diagnosticImport';
import {readBoundedJson} from '../boundedObservation';
import '../fortress.css';
import LiveObservation from '../components/LiveObservation';
type Scenario='ok'|'forbidden'|'tls-error';
export default function DigitalFortress(){
 const {locale}=useI18n(), fr=locale==='fr';
 const [scenario,setScenario]=useState<Scenario>('ok'),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(false),[result,setResult]=useState<unknown>(null);
 const [importError,setImportError]=useState(false);
 const seq=useRef(0),abort=useRef<AbortController|null>(null);
 const invalidate=()=>{seq.current++;abort.current?.abort();abort.current=null;setBusy(false);setResult(null);setError(false);};
 useEffect(()=>()=>{seq.current++;abort.current?.abort();},[]);
 const run=async()=>{if(!consent||busy)return;const id=++seq.current,controller=new AbortController();abort.current=controller;setBusy(true);setError(false);setResult(null);const timer=setTimeout(()=>{if(seq.current===id){seq.current++;abort.current=null;setBusy(false);setError(true);controller.abort();}},15_000);try{
  const options={credentials:'omit' as const,redirect:'error' as const,cache:'no-store' as const,signal:controller.signal};
  const bootstrap=await fetch('http://127.0.0.1:8007/api/fortress/mvp/capability',{...options,method:'GET',headers:{'X-Sentinel-Request':'sync'}});
  if(!bootstrap.ok){void bootstrap.body?.cancel().catch(()=>{});throw new Error('unavailable');}const capability:unknown=await readBoundedJson(bootstrap,1024,controller.signal);
  if(!capability||typeof capability!=='object'||typeof (capability as Record<string,unknown>).capability!=='string'||! /^[A-Za-z0-9_-]{32,128}$/.test((capability as {capability:string}).capability)||controller.signal.aborted||seq.current!==id)throw new Error('invalid');
  const response=await fetch('http://127.0.0.1:8007/api/fortress/mvp/demo',{...options,method:'POST',headers:{'X-Sentinel-Request':'sync','X-Sentinel-Capability':(capability as {capability:string}).capability,'Content-Type':'application/json'},body:JSON.stringify({scenario,consent:true})});
  // The fixture contract is a compact structured report, not raw HTTP content;
  // use the live-report ceiling with generous headroom for its fields and findings.
  if(!response.ok){void response.body?.cancel().catch(()=>{});throw new Error('unavailable');}const data:unknown=await readBoundedJson(response,256*1024,controller.signal);
  if(!data||typeof data!=='object'||Array.isArray(data)||(data as Record<string,unknown>).mode!=='fixture'||(data as Record<string,unknown>).scenario!==scenario)throw new Error('invalid');
  if(seq.current===id&&!controller.signal.aborted)setResult(data);
 }catch{if(seq.current===id&&!controller.signal.aborted)setError(true);controller.abort();}finally{clearTimeout(timer);if(seq.current===id){setBusy(false);abort.current=null;}}};
 const html=result?renderFortressReport(result,locale):'';
 const importFile=async(file:File|undefined)=>{invalidate();setImportError(false);const id=seq.current;if(!file)return;try{if(file.size>MAX_IMPORT_BYTES||!(file.type==='application/json'||(!file.type&&/\.json$/i.test(file.name))))throw new Error();const reader=new FileReader();const text=await new Promise<string>((resolve,reject)=>{reader.onerror=()=>reject();reader.onload=()=>typeof reader.result==='string'?resolve(reader.result):reject();reader.readAsText(file,'UTF-8');});const parsed=parseDiagnostic(text);if(seq.current===id)setResult(parsed);}catch{if(seq.current===id)setImportError(true);}};
 const download=()=>{if(!html)return;const url=URL.createObjectURL(new Blob([html],{type:'text/html;charset=utf-8'}));const a=document.createElement('a');a.href=url;const kind=result&&typeof result==='object'&&(result as {mode?:unknown}).mode==='import'?'import':'fixture';a.download=`digital-fortress-${kind}-${locale}.html`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
 return <div className="fortress-view"><LiveObservation/>
 <section className="panel fortress-panel"><h2>{fr?'Importer un diagnostic HTTPS':'Import an HTTPS diagnostic'}</h2><p>{fr?'Fichier JSON local uniquement, sans connexion réseau.':'Local JSON file only, without a network connection.'}</p><label className="fortress-label">{fr?'Fichier de diagnostic':'Diagnostic file'}<input type="file" accept="application/json,.json" onChange={e=>{const file=e.target.files?.[0];e.target.value='';void importFile(file);}}/></label>{importError&&<p role="alert">{fr?'Fichier invalide ou incompatible.':'Invalid or incompatible file.'}</p>}</section>
 <section className="panel fortress-panel"><p className="fortress-kicker">LOCAL / FIXTURE</p><h2>{fr?'Démonstration locale uniquement':'Local fixture demonstration only'}</h2><p>{fr?'Connexion HTTPS de boucle locale à une fixture détenue. Pair public et DNS simulés ; aucun site Internet n’est contacté. Route fixe : GET / (standard-lab.invalid).':'Loopback HTTPS connection to an owned fixture. Public peer and DNS simulated; no Internet site is contacted. Fixed route: GET / (standard-lab.invalid).'}</p><label className="fortress-label">{fr?'Scénario':'Scenario'}<select value={scenario} onChange={e=>{invalidate();setConsent(false);setScenario(e.target.value as Scenario);}}><option value="ok">HTTPS 200</option><option value="forbidden">HTTP 403</option><option value="tls-error">{fr?'Erreur TLS':'TLS error'}</option></select></label><label className="fortress-consent"><input type="checkbox" checked={consent} onChange={e=>{invalidate();setConsent(e.target.checked);}}/>{fr?'J’autorise la fixture locale sélectionnée.':'I consent to the selected local fixture.'}</label><button type="button" className="button fortress-start" disabled={!consent||busy} onClick={run}>{busy?(fr?'Exécution…':'Running…'):(fr?'Lancer la fixture locale':'Run local fixture')}</button>{error&&<p role="alert">{fr?'Démonstration indisponible ou réponse incompatible ; résultats indéterminés.':'Demo unavailable or incompatible response; results indeterminate.'}</p>}</section>
 {!!result&&<section className="panel fortress-panel"><h2>{fr?'Rapport local':'Local report'}</h2><p>{fr?'L’aperçu et l’export utilisent exactement le même rendu.':'Preview and download use exactly the same renderer.'}</p><button type="button" className="button" onClick={download}>{fr?'Télécharger le rapport HTML':'Download HTML report'} · {locale.toUpperCase()}</button><iframe title={fr?'Aperçu du rapport':'Report preview'} className="fortress-preview" sandbox="" srcDoc={html}/></section>}</div>;
}
