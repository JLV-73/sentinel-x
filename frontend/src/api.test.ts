import { describe, it, expect, vi, afterEach } from 'vitest';
import { api, ApiError } from './api';
afterEach(() => vi.unstubAllGlobals());
describe('API locale sans données de repli', () => {
  it('encode les filtres exacts et transmet le signal d’annulation', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({items:[],total:0,page:1,page_size:20,pages:0})));
    vi.stubGlobal('fetch', fetcher);
    const controller = new AbortController();
    await api.catalogue({q:'CVE & Cisco',vendor:'Microsoft',ransomware:'Known',sort:'asc',page:2,page_size:20}, controller.signal);
    const [url, init] = fetcher.mock.calls[0];
    const params = new URL(url, 'http://localhost').searchParams;
    expect(params.get('q')).toBe('CVE & Cisco'); expect(params.get('vendor')).toBe('Microsoft');
    expect(params.get('ransomware')).toBe('Known'); expect(params.get('page')).toBe('2');
    expect(init.signal).toBe(controller.signal); expect(url).toMatch(/^\/api\/vulnerabilities\?/);
  });
  it('envoie le marqueur explicite de synchronisation sans corps ni source personnalisée', async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response('{"status":"success"}'));
    vi.stubGlobal('fetch', fetcher); await api.sync();
    expect(fetcher).toHaveBeenCalledWith('/api/sync', expect.objectContaining({method:'POST',headers:{'X-Sentinel-Request':'sync'}}));
    expect(fetcher.mock.calls[0][1].body).toBeUndefined();
  });
  it('expose le détail 502 au lieu de produire des données', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"detail":"Source officielle indisponible"}',{status:502})));
    await expect(api.summary()).rejects.toThrow('Source officielle indisponible');
  });
  it('constitue la liste exhaustive des éditeurs exacts à partir des pages du contrat', async () => {
    vi.stubGlobal('fetch',vi.fn(async (url:string) => {
      const page=new URL(url,'http://localhost').searchParams.get('page');
      return new Response(JSON.stringify({items:page==='1'?[{vendorProject:'Cisco'},{vendorProject:'Microsoft'}]:[{vendorProject:'Cisco'},{vendorProject:'Acme & Co'}],total:4,pages:2,page:Number(page),page_size:100}));
    }));
    expect(await api.vendors()).toEqual(['Acme & Co','Cisco','Microsoft']);
  });
  it('distingue une CVE absente avec son statut HTTP', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"detail":"Not found"}',{status:404})));
    await expect(api.detail('CVE-2026-1234')).rejects.toMatchObject({status:404});
    expect(new ApiError('absent',404)).toBeInstanceOf(Error);
  });
});
