import type { Summary, SyncStatus, Vulnerability, ImportRecord } from '../types';
// Explicit test-only synthetic objects. Never imported by application code.
export const record: ImportRecord = {id:1,status:'success',started_at:'2026-10-20T12:00:00Z',finished_at:'2026-10-20T12:00:01Z',source_canonical:'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',source_url:'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',catalog_version:'2026.10.20',date_released:'2026-10-20T12:00:00Z',record_count:2,sha256:'a'.repeat(64),error:null};
export const vuln: Vulnerability = {cveID:'CVE-2026-1234',vendorProject:'Microsoft',product:'Test Product',vulnerabilityName:'Test vulnerability name',dateAdded:'2026-10-20',shortDescription:'Description officielle de test.',requiredAction:'Apply vendor mitigations.',dueDate:'2026-11-10',knownRansomwareCampaignUse:'Known',notes:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',cwes:['CWE-79']};
export const summary: Summary = {data_mode:'REAL DATA',total:2,new_last_30_days:1,ransomware_known:1,vendor_count:2,added_by_month:[{period:'2026-09',count:1},{period:'2026-10',count:1}],top_vendors:[{vendor:'Microsoft',count:1},{vendor:'Cisco',count:1}],latest:[vuln],provenance:record,as_of_utc:'2026-10-20T12:00:01Z'};
export const status: SyncStatus = {data_mode:'REAL DATA',database:{status:'ok',integrity:'ok',count:2},last_attempt:record,last_success:record,history:[record],syncing:false};
export function json(value:unknown, code=200) { return new Response(JSON.stringify(value), {status:code,headers:{'Content-Type':'application/json'}}); }
export function defaultResponse(url:string) {
 if(url==='/api/health') return json({status:'ok',database:'ok',data_mode:'REAL DATA'});
 if(url==='/api/summary') return json(summary);
 if(url==='/api/sync/status') return json(status);
 if(url.startsWith('/api/vulnerabilities?')) return json({items:[vuln],total:1,page:1,page_size:20,pages:1});
 if(url.startsWith('/api/vulnerabilities/')) return json({vulnerability:vuln,provenance:record});
 return json({detail:'Route non prévue dans ce test'},404);
}
