import '../triage.css';
import {useState} from 'react';
import {ChevronLeft,ChevronRight} from 'lucide-react';
import {api} from '../api';
import {useApi} from '../hooks';
import {useI18n} from '../i18n';
import {initialTriageWorkspace,triageQuery,validateTriage,type TriageWorkspace} from '../triage';
import {Loading,ErrorState} from '../components/UI';
import TriageFacts from '../components/TriageFacts';
import TriageFilters from '../components/TriageFilters';
export default function Triage({open,workspace,setWorkspace}:{open:(id:string)=>void;workspace:TriageWorkspace;setWorkspace:(next:TriageWorkspace)=>void}){
 const {t,number}=useI18n();const [retry,setRetry]=useState(0);
 const {draft,query}=workspace;
 const results=useApi(signal=>api.triage(query,signal),`triage-${JSON.stringify(query)}-${retry}`);
 const errors=validateTriage(draft);
 const pending=Object.keys(errors).length>0||JSON.stringify(triageQuery(draft))!==JSON.stringify({...query,page:1});
 const data=results.data;
 return <div className="triage-view" data-testid="triage-view">
  <p className="triage-scope">{t('triageScope')}</p>
  <TriageFilters draft={draft} change={patch=>setWorkspace({...workspace,draft:{...draft,...patch}})} apply={()=>{if(Object.keys(errors).length)return;setWorkspace({...workspace,query:triageQuery(draft)});setRetry(v=>v+1);}} reset={()=>setWorkspace(initialTriageWorkspace)} pending={pending}/>
  <section className="panel triage-results" data-testid="triage-results" aria-busy={results.loading}>
   <div className="panel-heading"><h2>{t('triageFacts')}</h2>{data&&<span data-testid="triage-data-mode" data-mode={data.data_mode} className={`mode-badge ${data.data_mode==='REAL DATA'?'real':''}`}><span className="status-dot"/>{t(data.data_mode==='REAL DATA'?'realData':'noData')}</span>}{data&&<span data-testid="triage-count" className="muted">{t('triageResultCount',{total:number(data.total),catalog:number(data.catalog_total)})}</span>}</div>
   {results.loading?<Loading label={t('intelLoading')}/>:results.error?<ErrorState error={results.error} retry={()=>setRetry(v=>v+1)}/>:data?<TriageFacts data={data} open={open}/>:null}
   {data&&data.catalog_total>0&&<nav className="triage-pagination" aria-label={t('triagePages')}><span data-testid="triage-page">{t('page',{page:number(data.page),pages:number(data.pages)})}</span><div><button type="button" className="button" data-testid="triage-prev" aria-label={t('previous')} disabled={results.loading||data.page<=1} onClick={()=>setWorkspace({...workspace,query:{...query,page:data.page-1}})}><ChevronLeft size={16}/>{t('previous')}</button><button type="button" className="button" data-testid="triage-next" aria-label={t('next')} disabled={results.loading||data.page>=data.pages} onClick={()=>setWorkspace({...workspace,query:{...query,page:data.page+1}})}>{t('next')}<ChevronRight size={16}/></button></div></nav>}
  </section>
 </div>;
}
