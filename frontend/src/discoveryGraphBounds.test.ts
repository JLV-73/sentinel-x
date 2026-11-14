import {describe,it,expect} from 'vitest';
import {parseDiscoveryResponse} from './discoveryApi';
import {renderDiscoveryReport} from './discoveryReport';
import {report} from './components/DiscoveryReal';

function graph(n:number, privateView=false):any {
 const page={id:'page-1',route:'/',depth:0,status:403,state:'access_denied',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null};
 return {schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'depth_limit',requests:1,bytes:0,pages:[page],relations:Array.from({length:n-1},(_,i)=>({from:'page-1',to:`page-${i+2}`,kind:'link'})),resources:[],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion'],...(privateView?{private_paths:Array.from({length:n},(_,i)=>({id:`page-${i+1}`,path:'/'}))}:{})};
}
describe('bounded Discovery graph',()=>{
 it('explicitly reports omitted relations without changing crawl status',()=>{
  const value=graph(501,true); value.graph_omitted_relations=1200;
  const parsed=parseDiscoveryResponse(value,'live');
  expect(report(parsed,'fr')).toContain('Relations omises du graphe : 1200');
  expect(report(parsed,'en')).toContain('Graph relations omitted: 1200');
  expect(()=>parseDiscoveryResponse({...value,graph_omitted_relations:-1},'live')).toThrow();
 });
 it.each([501,999])('accepts %i nodes, retaining all relations and private aliases',n=>{
  const value=graph(n,true), before=JSON.stringify(value);
  expect(parseDiscoveryResponse(value,'live')).toEqual(value);
  expect(JSON.stringify(value)).toBe(before);
 });
 it('rejects a fourth-digit alias and private path injection',()=>{
  const tooLarge=graph(1000,true);expect(()=>parseDiscoveryResponse(tooLarge,'live')).toThrow();
  const bad=graph(501,true);bad.private_paths[500].path='/SECRET';expect(()=>parseDiscoveryResponse(bad,'live')).toThrow();
 });
 it.each([501,999])('renders %i explicitly bounded pages, preserving observed evidence',n=>{
  const pages:any[]=Array.from({length:n},(_,i)=>({route:[],label:`page-${i+1}`,depth:i?null:0,status:i?null:403,state:i?'not_visited':'blocked',observations:[]}));
  const report:any={provenance:'declared_observation',completeness:'incomplete',limits:['unknown'],pages,relations:[],resources:[]};
  for(const language of ['fr','en'] as const){const html=renderDiscoveryReport(report,language);expect(html).toContain(`page-${n}`);expect(html).toContain('403');}
  report.pages.push({route:[],label:'page-1000',depth:null,status:null,state:'not_visited',observations:[]});expect(()=>renderDiscoveryReport(report,'fr')).toThrow();
 });
});
