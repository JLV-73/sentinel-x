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
