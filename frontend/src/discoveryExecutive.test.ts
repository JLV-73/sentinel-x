import {it,expect} from 'vitest';
import {renderDiscoveryReport} from './discoveryReport';
import {report} from './components/DiscoveryReal';
import {parseDiscoveryResponse} from './discoveryApi';

it.each(['fr','en'] as const)('summarizes declared coverage and relations without losing evidence (%s)',lang=>{
 const page={route:[] as const,depth:0,status:200,state:'completed' as const,observations:[]};
 const data={provenance:'synthetic' as const,completeness:'complete' as const,limits:[],pages:[page,{...page,label:'page-2'}],relations:[{from:0,to:1,kind:'link' as const},{from:0,to:1,kind:'link' as const}],resources:[]};
 const html=renderDiscoveryReport(data,lang);
 expect(html).toContain('JLV Labs');expect(html).toContain('NIGHTFALL');
 expect(html).toContain(lang==='fr'?'2 relations déclarées':'2 declared relations');
 expect(html).toContain('<details');expect(html).toContain('page-2');
 expect(html).toContain(lang==='fr'?'pages terminées parmi les pages déclarées':'completed pages among declared pages');
});
it.each(['fr','en'] as const)('groups identical CSP projections while retaining per-page technical evidence (%s)',lang=>{
 const page={route:[] as const,depth:0,status:200,state:'completed' as const,observations:[]};
 const projection={active:{directives:[{directive:'script-src',unsafe_inline:true}],effective:[{sink:'script-elem',directive:'script-src',mode:'review'},{sink:'script-attr',directive:'script-src',mode:'review'}]},report_only:{directives:[],effective:[]}};
 const security={state:'analyzed' as const,hsts:'positive' as const,csp:'present' as const,csp_report_only:'absent' as const,cookies:'none_observed' as const,findings:[],csp_projection:projection};
 const html=renderDiscoveryReport({provenance:'synthetic',completeness:'complete',limits:[],pages:[page,{...page,label:'page-2'}],relations:[],resources:[],security:[{...security,page:0},{...security,page:1}]},lang);
 expect(html).toContain(lang==='fr'?'2 pages : même projection CSP':'2 pages: same CSP projection');
 expect(html).toContain('script-elem');expect(html).toContain('script-src');expect(html).toContain('page-2');
});
it.each(['fr','en'] as const)('displays only a validated worker origin in the executive summary (%s)',lang=>{
 const input=parseDiscoveryResponse({schema:'fortress.discovery/1',provenance:'live',complete:false,reason:'http_refused',requests:1,bytes:0,pages:[{id:'page-1',route:'page-1',depth:0,status:403,state:'access_denied',observed_at:'2026-11-12T12:00:00Z',findings:[],observations:null}],relations:[],resources:[],limits:['excluded_links:0','no_external_requests','no_authentication','headers_only_analysis','not_a_vulnerability_or_compliance_conclusion']},'live');
 const budgets={pages:5,requests:10,depth:1,interval:1,page_bytes:524288,total_bytes:3145728,seconds:120};
 const trace={id:null,origin:'https://example.invalid/',budgets};
 const summary=(html:string)=>html.split('<section class="summary"')[1].split('</section>')[0];
 const html=report(input,lang,'worker',trace);
 expect(html.indexOf('<header>')).toBeLessThan(html.indexOf('class="panel"'));
 expect(summary(html)).toContain('https://example.invalid/');
 expect(summary(report(input,lang,'historical',trace))).not.toContain('example.invalid');
 expect(summary(report(input,lang,'worker',{...trace,origin:'https://example.invalid/private?token=secret'}))).not.toContain('secret');
 expect(summary(report(input,lang,'historical',trace))).toMatch(lang==='fr'?/Origine HTTPS.*inconnue/i:/HTTPS origin.*unknown/i);
});
