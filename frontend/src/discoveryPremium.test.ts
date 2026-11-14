import {test, expect} from 'vitest';
import {renderDiscoveryReport, type DiscoveryReport} from './discoveryReport';

const page = (label:string) => ({route: [] as const, label, depth: 0, status: 200, state: 'completed' as const, observations: [{kind:'response' as const,state:'observed' as const,evidence:'http_status' as const}]});
const finding = {rule_id:'hsts.header_absent.v1',qualification:'confirmed',priority:'unclassified',evidence:'absent',recommendation:'review_hsts_for_route',limit:'response_headers_only'} as const;
const report:DiscoveryReport = {provenance:'synthetic',completeness:'incomplete',limits:['budget'],pages:[page('page-1'),page('page-2')],relations:[],resources:[],crawl:{pages:2,requests:2,bytes:100,complete:false,reason:'page_limit'},security:[0,1].map(page=>({page,state:'analyzed',hsts:'absent',csp:'absent',csp_report_only:'absent',cookies:'none_observed',findings:[finding]}))};
test('rapport bilingue structuré, constats consolidés et collecte bornée',()=>{
 for (const [lang, bounded, heading] of [['fr','Collecte bornée','Recommandations'],['en','Bounded collection','Recommendations']] as const) {
  const html=renderDiscoveryReport(report,lang);
  expect(html).toContain(bounded); expect(html).toContain(heading);
  expect(html).toMatch(/page-1[\s\S]*page-2/);
  expect(html.match(/<h4>hsts\.header_absent\.v1<\/h4>/g)).toHaveLength(1);
 }
});
test('le laboratoire reste identifié dans le document autonome',()=>{
 const html=renderDiscoveryReport({...report,provenance:'lab'},'fr');
 expect(html).toContain('Laboratoire local');
 expect(html).not.toContain('Observation déclarée — non attestée');
});
test('une limite de pages sans réponse ne devient pas une collecte réussie',()=>{
 const html=renderDiscoveryReport({...report,pages:[],security:[],crawl:{pages:0,requests:1,bytes:0,complete:false,reason:'page_limit'}},'fr');
 expect(html).not.toContain('Collecte bornée réussie');
});
