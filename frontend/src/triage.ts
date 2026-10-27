import type {TriageQuery,TriageStateFilter} from './types';
export interface TriageFilters {
 q:string; added_since:string; added_until:string; nvd_state:TriageStateFilter; epss_state:TriageStateFilter;
 cvss_availability:'all'|'scored'|'unscored'; cvss_min:string; epss_percent:string;
 recent_days:string; recent_only:boolean; sort:'asc'|'desc'; page_size:number;
}
export interface TriageWorkspace {draft:TriageFilters;query:TriageQuery}
export const initialTriageFilters:TriageFilters={q:'',added_since:'',added_until:'',nvd_state:'all',epss_state:'all',cvss_availability:'all',cvss_min:'',epss_percent:'',recent_days:'30',recent_only:false,sort:'desc',page_size:20};
export type TriageErrors=Partial<Record<keyof TriageFilters,import('./i18n').TranslationKey>>;
const decimal=(value:string)=>/^[+-]?(?:[0-9]+(?:[.,][0-9]*)?|[.,][0-9]+)(?:e[+-]?[0-9]+)?$/i.test(value)?Number(value.replace(',','.')):NaN;
function validDate(value:string){const date=new Date(`${value}T00:00:00Z`);return /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value)&&Number(value.slice(0,4))>=1&&!Number.isNaN(date.getTime())&&date.toISOString().slice(0,10)===value;}
export function validateTriage(filters:TriageFilters):TriageErrors {
 const errors:TriageErrors={};
 if(filters.q.length>200)errors.q='triageInvalidSearch';
 for(const key of ['added_since','added_until'] as const)if(filters[key]&&!validDate(filters[key]))errors[key]='triageInvalidDate';
 if(!errors.added_since&&!errors.added_until&&filters.added_since&&filters.added_until&&filters.added_since>filters.added_until)errors.added_until='triageInvalidRange';
 if(filters.cvss_min!==''&&(!Number.isFinite(decimal(filters.cvss_min))||decimal(filters.cvss_min)<0||decimal(filters.cvss_min)>10))errors.cvss_min='triageInvalidCvss';
 if(filters.epss_percent!==''&&(!Number.isFinite(decimal(filters.epss_percent))||decimal(filters.epss_percent)<0||decimal(filters.epss_percent)>100))errors.epss_percent='triageInvalidEpss';
 if(!/^[0-9]+$/.test(filters.recent_days)||Number(filters.recent_days)<1||Number(filters.recent_days)>3650)errors.recent_days='triageInvalidDays';
 return errors;
}
// Probability conversion belongs only at this UI-to-wire boundary.
export function triageQuery(filters:TriageFilters):TriageQuery {
 if(Object.keys(validateTriage(filters)).length)throw new RangeError('Invalid triage filters');
 const {epss_percent,cvss_min,recent_days,...rest}=filters;
 return {...rest,recent_days:Number(recent_days),...(cvss_min!==''?{cvss_min:decimal(cvss_min)}:{}),...(epss_percent!==''?{epss_min:decimal(epss_percent)/100}:{}),page:1};
}
export const initialTriageWorkspace:TriageWorkspace={draft:initialTriageFilters,query:triageQuery(initialTriageFilters)};
