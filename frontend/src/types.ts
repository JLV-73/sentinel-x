export interface Vulnerability {
  cveID: string; vendorProject: string; product: string; vulnerabilityName: string;
  dateAdded: string; shortDescription: string; requiredAction: string; dueDate: string;
  knownRansomwareCampaignUse?: 'Known' | 'Unknown'; notes?: string; cwes?: string[];
  [key: string]: unknown;
}
export interface ImportRecord {
  id: number; status: 'success' | 'failed'; started_at: string; finished_at: string | null;
  source_canonical: string; source_url: string | null; catalog_version: string | null;
  date_released: string | null; record_count: number | null; sha256: string | null; error: string | null;
  schema_sha256?: string; download_attempts?: unknown;
}
export interface Summary {
  data_mode: string; total: number; new_last_30_days: number; ransomware_known: number; vendor_count: number;
  added_by_month: {period: string; count: number}[]; top_vendors: {vendor: string; count: number}[];
  latest: Vulnerability[]; provenance: ImportRecord | null; as_of_utc: string;
}
export interface CatalogueFilters { q: string; vendor: string; ransomware: string; sort: 'asc' | 'desc'; page: number; page_size: number; added_since?: string }
export interface Catalogue { items: Vulnerability[]; total: number; page: number; page_size: number; pages: number }
export interface SyncStatus { data_mode: string; database: {status: string; integrity: string; count: number}; last_attempt: ImportRecord | null; last_success: ImportRecord | null; history: ImportRecord[]; syncing: boolean }
export interface Detail { vulnerability: Vulnerability; provenance: ImportRecord }

// P1-A is additive: the CISA catalogue and import records above stay unchanged.
export type IntelligenceState = 'not_requested'|'available'|'absent'|'unavailable'|'stale';
export type IntelligenceSource = 'nvd'|'epss';
export interface IntelligenceProvenance { source:IntelligenceSource; url:string; sha256:string; collected_at:string; raw_file:string }
export interface LeaseCleanup { cleanup_deferred?:boolean; cleanup_warning?:string }
export interface IntelligenceAttempt extends LeaseCleanup {
 id:number; source:IntelligenceSource; status:'success'|'partial'|'failed'; started_at:string; finished_at:string;
 requested:number; available:number; absent:number; failed:number; error:string|null; provenances:IntelligenceProvenance[];
}
export interface CvssEntry { version:string; base_score:number; base_severity:string|null; vector:string|null; source:string; type:string|null; record_modified:string }
export interface NvdData { id:string; published:string; last_modified:string; vuln_status:string|null; descriptions:{lang:string;value:string}[]; cvss:CvssEntry[]; weaknesses:unknown[]; references:unknown[]; configurations:unknown[] }
export interface EpssData { cve:string; epss:number; percentile:number; date:string }
export interface SourceData<T=NvdData|EpssData> extends LeaseCleanup {
 state:IntelligenceState; stale:boolean; retained_after_error:boolean; collected_at:string|null; source_date:string|null;
 data:T|null; provenance:IntelligenceProvenance|null; last_attempt:IntelligenceAttempt|null; last_success:IntelligenceAttempt|null;
}
export interface Intelligence { cve_id:string; nvd:SourceData<NvdData>; epss:SourceData<EpssData> }
export interface IntelligenceCoverage { available:number; with_scores:number; absent:number; unavailable:number; stale:number; not_requested:number }
export interface IntelligenceSourceStatus extends IntelligenceCoverage { source:IntelligenceSource; last_attempt:IntelligenceAttempt|null; last_success:IntelligenceAttempt|null; history:IntelligenceAttempt[]; freshness_hours:number; busy:boolean; endpoint:string }
export type IntelligenceStatus = Record<IntelligenceSource,IntelligenceSourceStatus>;
export interface IntelligenceSummary { catalog_total:number; nvd:IntelligenceCoverage; epss:IntelligenceCoverage }
// Read-only P1-B projection: collection attempt histories remain in detail.
export type TriageSource<T> = Pick<SourceData<T>,'state'|'stale'|'retained_after_error'|'collected_at'|'source_date'|'data'|'provenance'>;
export type TriageStateFilter = IntelligenceState|'all'|'needs_attention';
export interface TriageQuery {
 q?:string; added_since?:string; added_until?:string; nvd_state?:TriageStateFilter; epss_state?:TriageStateFilter;
 cvss_availability?:'all'|'scored'|'unscored'; cvss_min?:number; epss_min?:number;
 recent_days?:number; recent_only?:boolean; sort?:'asc'|'desc'; page?:number; page_size?:number;
}
export interface TriageItem {
 cve_id:string; kev:Vulnerability; nvd:TriageSource<NvdData>; epss:TriageSource<EpssData>;
 indicators:{recent_kev:boolean;cvss_threshold_met:boolean|null;epss_threshold_met:boolean|null;nvd_needs_enrichment:boolean;epss_needs_enrichment:boolean};
}
// P1-C is isolated: legacy NVD/EPSS source unions and endpoint shapes stay unchanged.
export interface GhsaCvss { vector_string:string|null; score:number|null; [key:string]:unknown }
export interface GhsaVulnerability {
 package:{ecosystem:string;name:string;[key:string]:unknown};
 vulnerable_version_range:string|null; first_patched_version:string|null;
 [key:string]:unknown;
}
export interface GhsaAdvisory {
 ghsa_id:string; cve_id:string|null; type:string; html_url:string; summary:string; description:string|null;
 severity:string|null; cvss:GhsaCvss|null; cvss_severities?:Record<string,GhsaCvss|null>|null;
 identifiers:{type:string;value:string}[]; vulnerabilities:GhsaVulnerability[];
 published_at:string|null; updated_at:string|null; github_reviewed_at:string|null;
 nvd_published_at:string|null; withdrawn_at:string|null; [key:string]:unknown;
}
export interface GhsaData { date:string|null; advisories:GhsaAdvisory[] }
export type GhsaProvenance=Omit<IntelligenceProvenance,'source'>&{source:'ghsa'};
export type GhsaAttempt=Omit<IntelligenceAttempt,'source'|'provenances'>&{source:'ghsa';provenances:GhsaProvenance[]};
export type GhsaSourceData=Omit<SourceData<GhsaData>,'provenance'|'last_attempt'|'last_success'>&{
 provenance:GhsaProvenance|null;last_attempt:GhsaAttempt|null;last_success:GhsaAttempt|null;
};
export interface GhsaResult {
 cve_id:string; ghsa:GhsaSourceData;
 control:{next_request_at:string|null;freshness_hours:24;minimum_interval_seconds:65;max_advisories:100;
 attribution:{name:string;url:string;license:string;license_url:string}};
}
export interface TriageResult {
 data_mode:'REAL DATA'|'NO DATA'; as_of_utc:string; catalog_total:number; total:number; page:number; pages:number; page_size:number;
 filters:TriageQuery; cisa_provenance:ImportRecord|null; items:TriageItem[];
}

export type FortressLevel='standard'|'deep';
export interface FortressParameter {url:string;name:string;kind:'reflection'|'redirect'}
export interface FortressRequest {target:string;additional_urls:string[];level:FortressLevel;authorized:true;parameters:FortressParameter[]}
export interface FortressFinding {id:string;status:'conformant'|'attention'|'suspected'|'confirmed'|'indeterminate';severity:string;reason:string;evidence:string;limitations:string;preconditions:string;recommendation:string;reference:string;method:string;route:string;date:string}
export interface FortressResult {audit_id:string;mode:string;started_at:string;finished_at:string;scope:{origin:string;paths:string[]};requests_used:number;complete:boolean;findings:FortressFinding[];limitations:string[]}
