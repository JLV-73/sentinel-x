import {describe,it,expect} from 'vitest';
import {parseDiscoveryResponse} from './discoveryApi';
import {report} from './components/DiscoveryReal';

const payload=()=>({schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'depth_limit',requests:1,bytes:0,pages:[{id:'page-1',route:'page-1',depth:0,status:403,state:'access_denied',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null}],relations:[],resources:[],limits:['excluded_links:10','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion'],exclusion_reasons:{external:2,query_fragment:0,sensitive:0,non_html_resource:0,invalid:0,out_of_scope:0,depth:3,unknown:1},private_paths:[{id:'page-1',path:'/about/[masqué]'}]});

describe.each(['fr','en'] as const)('exclusion coverage %s',locale=>{
 it('distinguishes total, classified reasons, unknown and unclassified references without private paths',()=>{
  const html=report(parseDiscoveryResponse(payload(),'live'),locale);
  for(const text of locale==='fr'?['Liens exclus : 10','Motifs détaillés : 6','Inconnu: 1','Non classées : 4','Profondeur: 3','références, pas des URL uniques']:['Excluded links: 10','Reasons detailed: 6','Unknown: 1','Unclassified: 4','Depth: 3','references, not unique URLs']) expect(html).toContain(text);
  expect(html).not.toContain('/about/[masqué]');
 });
 it('shows zero remainder when all references have a reported reason',()=>{
  const v=payload();v.limits[0]='excluded_links:6';
  expect(report(parseDiscoveryResponse(v,'live'),locale)).toContain(locale==='fr'?'Non classées : 0':'Unclassified: 0');
 });
 it('does not invent a classification for historical responses without reasons',()=>{
  const v:Partial<ReturnType<typeof payload>>=payload();delete v.exclusion_reasons;
  const html=report(parseDiscoveryResponse(v,'live'),locale);
  expect(html).toContain(locale==='fr'?'motifs non fournis':'reasons not provided');
  expect(html).not.toContain(locale==='fr'?'Non classées :':'Unclassified:');
 });
 it('rejects category sums exceeding the reported total',()=>{
  const v=payload();v.limits[0]='excluded_links:5';
  expect(()=>parseDiscoveryResponse(v,'live')).toThrow();
 });
});
