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
