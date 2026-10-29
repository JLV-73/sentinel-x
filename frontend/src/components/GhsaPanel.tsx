import {useEffect,useState} from 'react';
import {api} from '../api';
import type {ComponentType} from 'react';
import type {GhsaResult,GhsaSourceData,GhsaAdvisory} from '../types';
import {useApi} from '../hooks';
import {useVerifiedCollection} from '../intelligenceHooks';
import {useI18n} from '../i18n';
import {Panel,SafeLink} from './UI';
import {Field,JsonDisclosure,SourceMetadata,IntelligenceError} from './IntelligenceShared';
// SourceMetadata only reads source-neutral metadata, never data/source-specific fields.
// Its legacy P1-A signature is narrower than that runtime contract. Keep those
// endpoint types unchanged; this view-only bridge preserves the original GHSA values.
const GhsaMetadata=SourceMetadata as unknown as ComponentType<{value:GhsaSourceData}>;
export default function GhsaPanel({cveId}:{cveId:string}) {
 return <GhsaContent key={cveId} cveId={cveId}/>;
}
function GhsaContent({cveId}:{cveId:string}) {
 const {t}=useI18n();
 const read=async(signal:AbortSignal)=>{
  const value=await api.ghsa(cveId,signal);
  if(value.cve_id!==cveId)throw new Error('GHSA local CVE mismatch');
  return value;
 };
 const [retry,setRetry]=useState(0);
 const resource=useApi(read,`ghsa-${cveId}-${retry}`);
 const [snapshot,setSnapshot]=useState<GhsaResult|null>(null);
 useEffect(()=>{if(resource.data)setSnapshot(resource.data);},[resource.data]);
 const data=snapshot??resource.data;
 const action=useVerifiedCollection({
  write:(signal)=>api.fetchGhsa(cveId,data?.ghsa.state!=='not_requested',signal),
  read,apply:setSnapshot,invalidate:resource.invalidate,
  cleanupDeferred:result=>result.ghsa.cleanup_deferred===true,
  status:result=>result.ghsa.last_attempt?.status??'failed',
  verify:(result,current)=>{
   const a=result.ghsa.last_attempt,b=current.ghsa.last_attempt;
   return result.cve_id===cveId&&current.cve_id===cveId&&!!a&&!!b&&a.source==='ghsa'&&b.source==='ghsa'
    &&a.id===b.id&&a.status===b.status&&a.finished_at===b.finished_at
    &&(['requested','available','absent','failed'] as const).every(key=>a[key]===b[key])
    &&result.ghsa.state===current.ghsa.state&&!result.ghsa.retained_after_error&&!current.ghsa.retained_after_error
    &&!!result.ghsa.provenance?.sha256
    &&result.ghsa.provenance.sha256===current.ghsa.provenance?.sha256;
  },
 });
 return <div data-testid="ghsa-panel"><Panel title={t('ghsaTitle')} className="intelligence-panel" action={<button className="button" data-testid="ghsa-action" disabled={action.busy||resource.loading||!data} onClick={action.run}>{t(action.busy?'intelFetching':data?.ghsa.state==='not_requested'?'ghsaFetch':'ghsaRefresh')}</button>}><div className="intel-content">
  <p className="muted">{t('ghsaManual')}</p>
  {resource.loading&&<p role="status">{t('intelLoading')}</p>}
  {resource.error&&<><p>{t('ghsaReadError')}</p><IntelligenceError error={resource.error}/><button className="button" onClick={()=>setRetry(value=>value+1)}>{t('ghsaRetry')}</button></>}
  {action.message&&<p role={action.message==='intelVerified'?'status':'alert'} className={action.message==='intelVerified'?'text-cyan':'intel-warning'}>{t(action.message)}</p>}
  {action.problem&&<IntelligenceError error={action.problem}/>}
  {action.leaseDeferred&&<p role="alert" className="intel-warning">{t('intelCleanupDeferred')}</p>}
  {data&&<>
   <div data-testid="ghsa-state" data-state={data.ghsa.state}><GhsaMetadata value={data.ghsa}/></div>
   {data.ghsa.state==='not_requested'&&<p>{t('ghsaNotRequested')}</p>}
   {data.ghsa.state==='absent'&&<p>{t('ghsaAbsent')}</p>}
   {data.ghsa.state==='unavailable'&&<p>{t('ghsaUnavailable')}</p>}
   {data.ghsa.stale&&<p className="intel-warning">{t('ghsaStale')}</p>}
   <p className="muted">{t('ghsaPolicy',{seconds:data.control.minimum_interval_seconds,hours:data.control.freshness_hours,limit:data.control.max_advisories})}</p>
   {data.control.next_request_at&&<p className="intel-warning">{t('ghsaNextRequest')}{' · '}<time lang="en" dateTime={data.control.next_request_at}>{data.control.next_request_at}</time></p>}
   {data.ghsa.data?.advisories.map((advisory,i)=><Advisory key={`${advisory.ghsa_id}-${i}`} value={advisory}/>)}
   <p className="muted"><SafeLink href={data.control.attribution.url}>{data.control.attribution.name}</SafeLink>{' · '}<SafeLink href={data.control.attribution.license_url}>{data.control.attribution.license}</SafeLink></p>
   <p className="muted">{t('ghsaProjection')}</p>
  </>}
 </div></Panel></div>;
}

function Advisory({value:a}:{value:GhsaAdvisory}) {
 const {t}=useI18n();
 const metrics=[['cvss',a.cvss],...Object.entries(a.cvss_severities??{})] as const;
 const dates=[['ghsaPublished',a.published_at],['ghsaUpdated',a.updated_at],['ghsaReviewed',a.github_reviewed_at],['ghsaNvdPublished',a.nvd_published_at]] as const;
 return <article className="intel-dimension" data-testid="ghsa-advisory">
  <h3><SafeLink href={a.html_url}><span lang="en">{a.ghsa_id}</span></SafeLink></h3>
  <div className="official-marker">{t('ghsaOriginal')}</div>
  <h4 lang="en">{a.summary}</h4>
  <p lang="en" className="intel-description">{a.description??t('unspecified')}</p>
  {a.withdrawn_at?<p className="intel-warning"><strong>{t('ghsaWithdrawn')}</strong>{' · '}<time dateTime={a.withdrawn_at} lang="en">{a.withdrawn_at}</time></p>:<p className="muted">{t('ghsaNoWithdrawal')}</p>}
  <dl className="intel-fields">
   <Field label={t('ghsaType')}><span lang="en">{a.type}</span></Field>
   <Field label={t('intelSeverity')}><span lang="en">{a.severity??t('unspecified')}</span></Field>
   {dates.map(([label,value])=><Field key={label} label={t(label)}>{value?<time dateTime={value} lang="en">{value}</time>:t('unavailable')}</Field>)}
  </dl>
  <p className="muted">{t('ghsaDates')}</p>
  <h4>{t('ghsaMetrics')}</h4>
  {metrics.some(([,metric])=>metric!=null)?metrics.map(([name,metric])=>metric&&<div key={name} className="cvss-block">
   {metric.vector_string?<dl className="intel-fields" data-testid="ghsa-cvss"><Field label={t('intelMetricType')}><code lang="en">{name}</code></Field><Field label={t('intelVector')}><code lang="en">{metric.vector_string}</code></Field><Field label={t('intelScore')}><span lang="en">{metric.score??t('unspecified')}</span></Field></dl>:<p>{name} · {t('ghsaNoVector')}</p>}
  </div>):<p className="muted">{t('ghsaNoMetric')}</p>}
  <h4>{t('ghsaPackages')}</h4>
  {a.vulnerabilities.length?a.vulnerabilities.map((entry,i)=><div key={i} className="cvss-block" data-testid="ghsa-package"><dl className="intel-fields">
   <Field label={t('ghsaEcosystem')}><span lang="en">{entry.package.ecosystem}</span></Field>
   <Field label={t('ghsaPackage')}><code lang="en">{entry.package.name}</code></Field>
   <Field label={t('ghsaRange')}>{entry.vulnerable_version_range?<code lang="en">{entry.vulnerable_version_range}</code>:t('ghsaRangeMissing')}</Field>
   <Field label={t('ghsaPatched')}>{entry.first_patched_version?<code lang="en">{entry.first_patched_version}</code>:t('ghsaUnknownFix')}</Field>
  </dl></div>):<p className="muted">{t('ghsaNoPackages')}</p>}
  <JsonDisclosure label={t('ghsaIdentifiers')} value={a.identifiers}/>
  <JsonDisclosure label={t('ghsaJson')} value={a}/>
 </article>;
}
