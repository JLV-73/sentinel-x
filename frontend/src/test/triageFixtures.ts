import type {TriageItem,TriageResult,TriageSource,NvdData,EpssData} from '../types';
import {vuln,record} from './fixtures';
// Synthetic unit-test data, never imported by runtime code.
export const emptySource=<T,>():TriageSource<T>=>({state:'not_requested',stale:false,retained_after_error:false,collected_at:null,source_date:null,data:null,provenance:null});
export function triageItem():TriageItem {return {
 cve_id:vuln.cveID,kev:{...vuln},
 nvd:{...emptySource<NvdData>(),state:'unavailable',stale:true,retained_after_error:true,collected_at:'2026-10-20T12:00:00Z',source_date:'2026-10-19T23:00:00Z',provenance:{source:'nvd',url:'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+vuln.cveID,sha256:'b'.repeat(64),raw_file:'nvd/test.json',collected_at:'2026-10-20T12:00:00Z'},data:{id:vuln.cveID,published:'2026-10-01T01:00:00Z',last_modified:'2026-10-19T23:00:00Z',vuln_status:'Analyzed',descriptions:[],weaknesses:[],references:[],configurations:[],cvss:[{version:'3.1',source:'nvd@nist.gov',type:'Primary',base_score:0,base_severity:'NONE',vector:'CVSS:3.1/AV:L',record_modified:'2026-10-19T23:00:00Z'},{version:'4.0',source:'vendor@example.test',type:'Secondary',base_score:9.8,base_severity:'CRITICAL',vector:'CVSS:4.0/AV:N',record_modified:'2026-10-19T23:00:00Z'}]}},
 epss:{...emptySource<EpssData>(),state:'available',collected_at:'2026-10-27T10:00:00Z',source_date:'2026-10-26',provenance:{source:'epss',url:'https://api.first.org/data/v1/epss?cve='+vuln.cveID,sha256:'c'.repeat(64),raw_file:'epss/test.json',collected_at:'2026-10-27T10:00:00Z'},data:{cve:vuln.cveID,epss:0,percentile:0.823,date:'2026-10-26'}},
 indicators:{recent_kev:true,cvss_threshold_met:null,epss_threshold_met:null,nvd_needs_enrichment:true,epss_needs_enrichment:false}
};}
export function triageResult(patch:Partial<TriageResult>={}):TriageResult{return {data_mode:'REAL DATA',as_of_utc:'2026-10-27T12:00:00Z',catalog_total:41,total:41,page:1,pages:3,page_size:20,filters:{},cisa_provenance:record,items:[triageItem()],...patch};}
