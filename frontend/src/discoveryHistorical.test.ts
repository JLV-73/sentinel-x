import {it,expect} from 'vitest';
import {report} from './components/DiscoveryReal';
import {parseDiscoveryResponse} from './discoveryApi';

const fixture = () => parseDiscoveryResponse({schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'page_limit',requests:1,bytes:10,pages:[{id:'page-1',route:'page-1',depth:0,status:403,state:'access_denied',observed_at:'2026-01-01T00:00:00Z',findings:[],observations:null}],relations:[],resources:[{page:'page-1',kind:'script',count:2}],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion']},'live');
it.each(['fr','en'] as const)('reports a page limit, references and unknown historical TLS (%s)',lang=>{
 const html=report(fixture(),lang,'historical');
 expect(html).toContain(lang==='fr'?'Limite de pages atteinte':'Page limit reached');
 expect(html).not.toContain(lang==='fr'?'Limite indéterminée':'Unknown limitation');
 expect(html).toContain(lang==='fr'?'couverture partielle':'partial coverage');
 expect(html).toContain(lang==='fr'?'non dédupliquées':'not deduplicated');
 expect(html).toContain(lang==='fr'?'non téléchargées':'not downloaded');
 expect(html).toContain(lang==='fr'?'TLS : inconnu':'TLS: unknown');
 expect(html.toLowerCase()).toContain(lang==='fr'?'relecture':'review');
 expect(html).toContain(lang==='fr'?'Méthode inconnue':'Method unknown');
});
it.each(['fr','en'] as const)('does not confer worker method on arbitrary data (%s)',lang=>{
 expect(report(fixture(),lang)).toContain(lang==='fr'?'Méthode inconnue':'Method unknown');
 expect(report(fixture(),lang,'worker')).toContain(lang==='fr'?'Méthode GET':'GET method');
});

it('masks display routes without breaking finding attribution',()=>{
 const x:any=fixture(); const p=x.pages[0]; Object.assign(p,{route:'/products',status:200,state:'complete',observations:{http_status:200,hsts:'absent',csp:'absent',csp_report_only:'absent',csp_directives:[],csp_report_only_directives:[],csp_effective:[],csp_report_only_effective:[],cookie_prefix:{state:'none_observed',violations:null},x_content_type_options:'present',referrer_policy:'absent',permissions_policy:'absent',cookies:{state:'none_observed',count:0,secure:null,httponly:null,samesite:null}},findings:[{route:'/products',confidence:'caller_declared',provenance:'response_headers',rule_id:'hsts.header_absent.v1',qualification:'confirmed',priority:'unclassified',evidence:'absent',recommendation:'review_hsts_for_route',limit:'response_headers_only'}]});
 const parsed=parseDiscoveryResponse(x,'live'); const html=report(parsed,'fr','historical'); expect(html).not.toContain('/products'); expect(html).toContain('hsts.header_absent.v1');
});
