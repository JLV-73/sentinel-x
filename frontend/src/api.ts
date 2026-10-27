import type { CatalogueFilters, Catalogue, Summary, SyncStatus, Detail, ImportRecord, Intelligence, IntelligenceStatus, IntelligenceSummary, SourceData, NvdData, IntelligenceAttempt } from './types';
export type ApiErrorCode='unreadable'|'http'|'source'|'busy'|'cooldown'|'database'|'notFound'|'validation';
function errorCode(status:number,detail:string):ApiErrorCode {
 if(status===404)return 'notFound';if(status===422)return 'validation';if(status===502)return 'source';if(status===503)return 'database';
 if(status===409)return /cooldown|interval|wait|60/i.test(detail)?'cooldown':'busy';return 'http';
}
export class ApiError extends Error { public code:ApiErrorCode; constructor(public detail:string,public status:number,code?:ApiErrorCode){super(detail||`HTTP ${status}`);this.code=code??errorCode(status,detail);} }
async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {cache:'no-store', ...options});
  let body: unknown;
  try { body = await response.json(); } catch { throw new ApiError('',response.status,'unreadable'); }
  if (!response.ok) {
    const detail = (body as {detail?:unknown})?.detail;
    throw new ApiError(typeof detail === 'string' ? detail : path.startsWith('/intelligence')&&detail!=null ? JSON.stringify(detail,null,2) : '', response.status);
  }
  return body as T;
}
export const api = {
  intelligence: (id:string,signal?:AbortSignal) => request<Intelligence>(`/intelligence/${encodeURIComponent(id)}`,{signal}),
  intelligencePage: (ids:string[],signal?:AbortSignal) => request<{items:Record<string,Intelligence>}>(`/intelligence?${new URLSearchParams({cve:ids.join(',')})}`,{signal}),
  intelligenceStatus: (signal?:AbortSignal) => request<IntelligenceStatus>('/intelligence/status',{signal}),
  intelligenceSummary: (signal?:AbortSignal) => request<IntelligenceSummary>('/intelligence/summary',{signal}),
  fetchNvd: (id:string,refresh:boolean,signal?:AbortSignal) => request<SourceData<NvdData>>(`/intelligence/nvd/${encodeURIComponent(id)}?refresh=${refresh}`,{method:'POST',headers:{'X-Sentinel-Request':'sync'},signal}),
  fetchEpss: (signal?:AbortSignal) => request<IntelligenceAttempt>('/intelligence/epss',{method:'POST',headers:{'X-Sentinel-Request':'sync'},signal}),
  summary: (signal?:AbortSignal) => request<Summary>('/summary', {signal}),
  health: (signal?:AbortSignal) => request<{status:string;database:string;data_mode:string}>('/health', {signal}),
  catalogue: (filters:CatalogueFilters, signal?:AbortSignal) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key,value]) => { if (value !== '' && value !== undefined) params.set(key,String(value)); });
    return request<Catalogue>(`/vulnerabilities?${params}`, {signal});
  },
  detail: (id:string,signal?:AbortSignal) => request<Detail>(`/vulnerabilities/${encodeURIComponent(id)}`, {signal}),
  status: (signal?:AbortSignal) => request<SyncStatus>('/sync/status', {signal}),
  // The P0 contract has no /vendors endpoint. Read its documented local pages
  // to build an exhaustive, exact list rather than silently limiting to top_vendors.
  vendors: async (signal?:AbortSignal):Promise<string[]> => {
    const vendors = new Set<string>(); let page=1; let pages=1;
    do {
      const result=await request<Catalogue>(`/vulnerabilities?sort=desc&page=${page}&page_size=100`,{signal});
      result.items.forEach(item=>vendors.add(item.vendorProject));
      pages=result.pages; page++;
    } while(page<=pages);
    return [...vendors].sort((a,b)=>a.localeCompare(b,'fr'));
  },
  sync: () => request<ImportRecord>('/sync', {method:'POST',headers:{'X-Sentinel-Request':'sync'}}),
};
