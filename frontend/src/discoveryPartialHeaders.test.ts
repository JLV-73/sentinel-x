import {it,expect} from 'vitest';
import {renderDiscoveryReport,type DiscoveryReport} from './discoveryReport';
import {partialHeaderNames} from './discoveryPartialHeaders';

const report=(present:readonly string[])=>({provenance:'declared_observation',completeness:'incomplete',limits:['unknown'],pages:[{route:[],label:'page-1',depth:0,status:500,state:'indeterminate',observations:[],partial_headers:{present,completeness:'headers_validated_body_incomplete'}}],relations:[],resources:[]} as unknown as DiscoveryReport);
it.each(['fr','en'] as const)('renders only supplied partial header names and empty presence in %s',language=>{
 const html=renderDiscoveryReport(report(partialHeaderNames),language);
 for(const name of partialHeaderNames) expect(html).toContain(name);
 expect(html).toContain(language==='fr'?'Corps incomplet':'Body incomplete');
 expect(html).not.toMatch(/SECRET_TEST|hsts\.header_absent|<strong>Conforme<\/strong>|<strong>Compliant<\/strong>/i);
 const empty=renderDiscoveryReport(report([]),language);
 expect(empty).toContain(language==='fr'?'aucun nom signalé':'no names reported');
 expect(empty).not.toContain('set-cookie');
});
it('rejects unsafe partial-header fields even when report renderer is called directly',()=>{
 const value=report(['set-cookie']) as any;
 for(const changes of [{present:['SET-COOKIE']},{present:['set-cookie','set-cookie']},{present:['SECRET_TEST']},{value:'SECRET_TEST'},{completeness:'complete'}]){
  const page=value.pages[0];
  expect(()=>renderDiscoveryReport({...value,pages:[{...page,partial_headers:{...page.partial_headers,...changes}}]},'en')).toThrow();
 }
 expect(()=>renderDiscoveryReport({...value,pages:[{...value.pages[0],state:'completed'}]},'en')).toThrow();
});
