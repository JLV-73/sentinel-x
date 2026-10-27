import {Search,RotateCcw} from 'lucide-react';
import {useI18n} from '../i18n';
import {validateTriage,type TriageFilters as Filters} from '../triage';
import type {TriageStateFilter} from '../types';
import {stateKeys} from './IntelligenceShared';
export default function TriageFilters({draft,change,apply,reset,pending}:{draft:Filters;change:(patch:Partial<Filters>)=>void;apply:()=>void;reset:()=>void;pending:boolean}){
 const {t}=useI18n();
 const errors=validateTriage(draft);
 const validation=(field:keyof Filters)=>({'aria-invalid':errors[field]?true:undefined,'aria-describedby':errors[field]?`triage-error-${field}`:undefined});
 const states=(['not_requested','available','absent','unavailable','stale'] as const).map(state=><option key={state} value={state}>{t(stateKeys[state])}</option>);
 return <form className="filter-panel triage-filters" data-testid="triage-filters" aria-label={t('triageFilters')} onSubmit={event=>{event.preventDefault();if(Object.keys(errors).length){event.currentTarget.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();return;}apply();}}>
  <div className="triage-search-row"><label className="search-field"><Search size={18}/><span className="sr-only">{t('searchLabel')}</span><input data-testid="triage-search" {...validation('q')} type="search" maxLength={200} placeholder={t('searchPlaceholder')} value={draft.q} onChange={e=>change({q:e.target.value})}/></label><button className="button primary" type="submit" data-testid="triage-apply">{t('triageApply')}</button><button className="button" type="button" data-testid="triage-reset" onClick={reset}><RotateCcw size={14}/>{t('reset')}</button></div>
  <div className="triage-calendar-filters">
   <label>{t('since')}<input type="date" data-testid="triage-added-since" {...validation('added_since')} value={draft.added_since} onChange={e=>change({added_since:e.target.value})}/></label>
   <label>{t('triageUntil')}<input type="date" data-testid="triage-added-until" {...validation('added_until')} value={draft.added_until} onChange={e=>change({added_until:e.target.value})}/></label>
   <label>{t('triageRecentDays')}<input inputMode="numeric" data-testid="triage-recent-days" {...validation('recent_days')} value={draft.recent_days} onChange={e=>change({recent_days:e.target.value})}/></label>
   <label>{t('sort')}<select data-testid="triage-sort" value={draft.sort} onChange={e=>change({sort:e.target.value as 'asc'|'desc'})}><option value="desc">{t('newest')}</option><option value="asc">{t('oldest')}</option></select></label>
   <label>{t('perPage')}<select data-testid="triage-page-size" value={draft.page_size} onChange={e=>change({page_size:Number(e.target.value)})}>{[10,20,50,100].map(size=><option key={size} value={size}>{size}</option>)}</select></label>
  </div>
  <div className="triage-source-filters">
   <fieldset><legend>NVD / CVSS</legend><div className="triage-nvd-controls"><label>{t('triageNvdState')}<select data-testid="triage-nvd-filter" value={draft.nvd_state} onChange={e=>change({nvd_state:e.target.value as TriageStateFilter})}><option value="all">{t('triageAllStates')}</option>{states}<option value="needs_attention">{t('triageNeedsAttention')}</option></select></label><label>{t('triageCvssAvailability')}<select data-testid="triage-cvss-availability" value={draft.cvss_availability} onChange={e=>change({cvss_availability:e.target.value as Filters['cvss_availability']})}><option value="all">{t('triageAllMetrics')}</option><option value="scored">{t('triageScored')}</option><option value="unscored">{t('triageUnscored')}</option></select></label><label>{t('triageCvssMin')}<input inputMode="decimal" data-testid="triage-cvss-min" {...validation('cvss_min')} value={draft.cvss_min} placeholder="—" onChange={e=>change({cvss_min:e.target.value})}/></label></div></fieldset>
   <fieldset><legend>FIRST / EPSS</legend><div className="triage-epss-controls"><label>{t('triageEpssState')}<select data-testid="triage-epss-filter" value={draft.epss_state} onChange={e=>change({epss_state:e.target.value as TriageStateFilter})}><option value="all">{t('triageAllStates')}</option>{states}<option value="needs_attention">{t('triageNeedsAttention')}</option></select></label><label>{t('triageEpssMin')}<input inputMode="decimal" data-testid="triage-epss-percent" {...validation('epss_percent')} value={draft.epss_percent} placeholder="—" onChange={e=>change({epss_percent:e.target.value})}/></label></div></fieldset>
  </div>
  <label className="triage-check"><input type="checkbox" data-testid="triage-recent-only" checked={draft.recent_only} onChange={e=>change({recent_only:e.target.checked})}/>{t('triageRecentOnly')}</label>
  <p className="triage-help" id="triage-retained-policy">{t('triageRetainedPolicy')}</p><p className="triage-help">{t('triageAttentionPolicy')}</p><p className="triage-help">{t('triageRecencyPolicy')}</p>
  {Object.keys(errors).length>0&&<div role="alert" className="triage-errors">{Object.entries(errors).map(([field,key])=><p key={field} id={`triage-error-${field}`} data-testid={`triage-error-${field}`}>{t(key)}</p>)}</div>}
  {pending&&<p className="triage-pending" role="status" data-testid="triage-pending">{t('triagePending')}</p>}
 </form>;
}
