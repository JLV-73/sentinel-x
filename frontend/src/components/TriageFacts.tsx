import {intlLocale,useI18n} from '../i18n';
import type {TriageItem,TriageSource,TriageResult} from '../types';
import {Empty,SafeLink,Provenance} from './UI';
import {CollectionProvenance,IntelligenceStateBadge,JsonDisclosure} from './IntelligenceShared';

export function SourceTime({value,testId}:{value:string|null;testId?:string}){
 const {date,locale,t}=useI18n();
 if(!value)return <span data-testid={testId}>{t('unavailable')}</span>;
 const parsed=new Date(value);
 const text=Number.isNaN(parsed.getTime())?t('invalidDate'):/^\d{4}-\d{2}-\d{2}$/.test(value)?date(value):new Intl.DateTimeFormat(intlLocale(locale),{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',timeZone:'UTC',timeZoneName:'short'}).format(parsed);
 return <time dateTime={value} title={value} data-testid={testId}>{text}</time>;
}
function SourceFacts({source,name}:{source:TriageSource<unknown>;name:'nvd'|'epss'}){
 const {t}=useI18n();
 return <div className="triage-source-meta">
  <div className="intel-state" data-testid={`triage-${name}-state`} data-state={source.state} data-stale={source.stale}>
   <IntelligenceStateBadge state={source.state}/>{source.stale&&source.state!=='stale'&&<IntelligenceStateBadge state="stale"/>}
  </div>
  {source.retained_after_error&&<p className="triage-retained">{t('intelRetained')}</p>}
  <dl className="triage-dates"><div><dt>{t('intelCollected')}</dt><dd><SourceTime value={source.collected_at} testId={`triage-${name}-collected`}/></dd></div><div><dt>{t('intelSourceDate')}</dt><dd><SourceTime value={source.source_date} testId={`triage-${name}-source-date`}/></dd></div></dl>
  <CollectionProvenance value={source.provenance}/>
 </div>;
}
function TriageRow({item,open}:{item:TriageItem;open:(id:string)=>void}){
 const {t,number,locale}=useI18n();
 const percent=(value:number)=>new Intl.NumberFormat(intlLocale(locale),{style:'percent',maximumFractionDigits:6}).format(value);
 const cvss=item.nvd.data?.cvss??[],epss=item.epss.data,flags=item.indicators;
 const criteria=[flags.recent_kev&&'triageRecent',flags.cvss_threshold_met===true&&'triageCvssMet',flags.epss_threshold_met===true&&'triageEpssMet',flags.nvd_needs_enrichment&&'triageNvdMissing',flags.epss_needs_enrichment&&'triageEpssMissing'] as const;
 return <tr data-testid={`triage-row-${item.cve_id}`}>
  <td><span className="tag tag-cyan">CISA KEV</span><button className="cve-link" data-testid="triage-open-detail" aria-label={t('inspectCve',{id:item.cve_id})} onClick={()=>open(item.cve_id)}>{item.cve_id}</button><strong lang="en">{item.kev.vendorProject}</strong><span lang="en">{item.kev.product}</span><p className="triage-vuln-name" lang="en">{item.kev.vulnerabilityName}</p><dl className="triage-dates"><div><dt>{t('added')}</dt><dd><SourceTime value={item.kev.dateAdded}/></dd></div></dl><div className="triage-links"><SafeLink href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA</SafeLink><SafeLink href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(item.cve_id)}`}>NVD</SafeLink><SafeLink href="https://www.first.org/epss/">FIRST</SafeLink></div></td>
  <td data-testid="triage-cvss"><div className="triage-metrics">{cvss.length?cvss.map((metric,index)=><div className="triage-metric" key={`${metric.version}-${metric.source}-${index}`}><div><span className="mono">CVSS {metric.version}</span><strong data-testid={`cvss-value-${index}`}>{number(metric.base_score)}<small> / 10</small></strong></div><span lang="en">{metric.source}</span><details><summary>{t('triageMetrics')}</summary><dl className="triage-dates"><div><dt>{t('intelMetricType')}</dt><dd lang="en">{metric.type??t('unspecified')}</dd></div><div><dt>{t('intelSeverity')}</dt><dd lang="en">{metric.base_severity??t('unspecified')}</dd></div><div><dt>{t('intelVector')}</dt><dd><code>{metric.vector??t('unspecified')}</code></dd></div><div><dt>{t('intelModified')}</dt><dd><SourceTime value={metric.record_modified}/></dd></div></dl></details></div>):<p className="muted">{t(item.nvd.data?'intelNoCvss':'triageNoNvd')}</p>}</div><SourceFacts source={item.nvd} name="nvd"/></td>
  <td><dl className="triage-epss-values"><div><dt>{t('triageProbability')}</dt><dd data-testid="triage-probability">{epss?percent(epss.epss):t('unavailable')}</dd></div><div><dt>{t('triagePercentile')}</dt><dd data-testid="triage-percentile">{epss?number(epss.percentile*100):t('unavailable')}</dd></div></dl><p className="triage-help">{t('intelPercentileBody')}</p>{epss&&<dl className="triage-dates"><div><dt>{t('intelScoreDate')}</dt><dd><SourceTime value={epss.date}/></dd></div></dl>}<SourceFacts source={item.epss} name="epss"/></td>
  <td><div className="triage-criteria" data-testid="triage-criteria">{criteria.filter(Boolean).map(key=>key&&<span key={key} className="tag tag-muted">{t(key)}</span>)}{!criteria.some(Boolean)&&<span className="muted">{t('triageNoCriteria')}</span>}</div><JsonDisclosure label={t('originalData')} value={item.kev}/></td>
 </tr>;
}
export default function TriageFacts({data,open}:{data:TriageResult;open:(id:string)=>void}){
 const {t}=useI18n();
 return <>
  <div className="triage-snapshot">{t('triageSnapshot')} <SourceTime value={data.as_of_utc}/></div>
  {data.catalog_total===0?<Empty title={t('noCatalogue')}/>:data.items.length===0?<Empty title={t('noMatch')}><p>{t('widen')}</p></Empty>:<div className="table-scroll"><table className="triage-table"><caption className="sr-only">{t('triageFacts')}</caption><thead><tr><th>{t('cveColumn')} / CISA KEV</th><th>{t('intelNvd')}</th><th>{t('intelEpss')}</th><th>{t('triageCriteria')}</th></tr></thead><tbody>{data.items.map(item=><TriageRow key={item.cve_id} item={item} open={open}/>)}</tbody></table></div>}
  <details className="triage-cisa-provenance"><summary>{t('triageCisaProvenance')}</summary><Provenance record={data.cisa_provenance}/></details>
 </>;
}
