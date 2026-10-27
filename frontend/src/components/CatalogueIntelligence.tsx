import {useState} from 'react';
import {api} from '../api';
import {useApi} from '../hooks';
import {useI18n} from '../i18n';
import type {Vulnerability} from '../types';
import {VulnerabilityTable} from './UI';
import {stateKeys} from './IntelligenceShared';
// Only the currently rendered CISA page is enriched, by a local GET. Catalogue
// search, filter, sort and pagination parameters are deliberately not involved.
export default function CatalogueIntelligence({items,open}:{items:Vulnerability[];open:(id:string)=>void}) {
 const {t}=useI18n();const [retry,setRetry]=useState(0);
 const ids=items.map(item=>item.cveID);
 const resource=useApi(signal=>api.intelligencePage(ids,signal),`page-intelligence-${ids.join(',')}-${retry}`);
 return <>{resource.error&&<div className="intel-catalogue-feedback" role="status">{t('intelCatalogueError')} <button className="text-button" onClick={()=>setRetry(v=>v+1)}>{t('intelReadRetry')}</button></div>}<VulnerabilityTable items={items} open={open} rowExtra={id=>{
  const value=resource.data?.items[id];if(!value)return null;
  return <span className="intel-indicators">{(['nvd','epss'] as const).map(source=>{const item=value[source];const hasScore=source==='nvd'?!!value.nvd.data?.cvss.length:value.epss.data!==null;
   const label=item.state==='available'&&!hasScore?t('intelNoScoresShort'):t(stateKeys[item.state]);
   return <span className={`intel-indicator ${item.state==='available'&&hasScore?'text-cyan':item.state==='stale'||item.state==='unavailable'?'text-amber':'muted'}`} key={source}>{t(source==='nvd'?'intelCvssIndicator':'intelEpssIndicator',{state:label})}{item.retained_after_error?` · ${t('intelRetainedShort')}`:''}</span>;
  })}</span>;
 }}/></>;
}
