import {describe,it,expect} from 'vitest';
import {parseObservation,renderLiveReport,validInput} from './liveObservation';
const input='https://example.org/private?secret=1';
const good=()=>({mode:'live',target:'https://example.org/',observed_at:'2026-01-01T00:00:00Z',http_status:200,tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3',not_before:'Jan  1 00:00:00 2026 GMT',not_after:'Jan  1 00:00:00 2027 GMT'},headers:{hsts:'present',csp:'absent',x_content_type_options:'present',referrer_policy:'present',permissions_policy:'absent'},failure_code:'none'});
describe('live observation contract',()=>{
 it('rejects invalid URLs and credentials',()=>{for(const u of ['http://example.org/','https://user:pass@example.org/','https://example.org/#fragment','not-url'])expect(validInput(u)).toBe(false);expect(validInput(input)).toBe(true);});
 it('rejects leaked paths, wrong origins, extra fields, wrong types and contradictory results',()=>{
  const cases:unknown[]=[{...good(),target:input},{...good(),target:'https://other.example/'},{...good(),secret:'x'},{...good(),headers:{...good().headers,hsts:['present']}},{...good(),tls:{...good().tls,hostname:['verified']}},{...good(),http_status:null},{...good(),failure_code:'timeout'},{...good(),observed_at:'yesterday'}];
  for(const raw of cases)expect(()=>parseObservation(raw,input)).toThrow();
 });
 it('rejects impossible UTC calendar dates without normalizing them',()=>{
  for(const observed_at of ['2026-02-31T00:00:00Z','2025-02-29T12:00:00+00:00','2026-04-31T23:59:59.123456Z'])expect(()=>parseObservation({...good(),observed_at},input)).toThrow();
  for(const observed_at of ['2024-02-29T12:00:00Z','2026-04-30T23:59:59.123456+00:00'])expect(parseObservation({...good(),observed_at},input).observed_at).toBe(observed_at);
 });
 it('rejects TLS and response contradictions while accepting valid failures',()=>{
  const g=good(), headers=Object.fromEntries(Object.keys(g.headers).map(k=>[k,'indeterminate']));
  const blocked={...g,http_status:null,headers,failure_code:'blocked',tls:{certificate:'indeterminate',hostname:'indeterminate',protocol:null,not_before:null,not_after:null}};
  expect(parseObservation(blocked,input)).toEqual(blocked);
  const cases=[{...blocked,tls:{...blocked.tls,certificate:'verified'}},{...blocked,tls:{...blocked.tls,protocol:'TLSv1.3'}},{...blocked,tls:{...blocked.tls,not_before:g.tls.not_before}},{...g,tls:{...g.tls,protocol:null}},{...g,tls:{...g.tls,not_after:null}},{...g,tls:{...g.tls,not_before:'2026-01-01T00:00:00Z'}},{...g,headers:{...g.headers,hsts:'indeterminate'}},{...blocked,failure_code:'none'},{...g,http_status:403,failure_code:'none'}];
  for(const raw of cases)expect(()=>parseObservation(raw,input)).toThrow();
 });
 it.each(['fr','en'] as const)('renders a blocked %s attempt without claiming HEAD was performed',locale=>{
  const g=good(), blocked={...g,http_status:null,headers:Object.fromEntries(Object.keys(g.headers).map(k=>[k,'indeterminate'])),failure_code:'blocked',tls:{certificate:'indeterminate',hostname:'indeterminate',protocol:null,not_before:null,not_after:null}};
  const report=renderLiveReport(parseObservation(blocked,input),locale);
  expect(report).toContain(locale==='fr'?'Provenance : tentative d’observation HTTPS HEAD':'Provenance: HTTPS HEAD observation attempt');
 });
 it.each(['fr','en'] as const)('renders a cautious separate %s report without the secret',locale=>{
  const report=renderLiveReport(parseObservation(good(),input),locale);
  expect(report).toContain('HEAD');expect(report).not.toContain('secret=1');expect(report).not.toContain('/private');
  expect(report).toMatch(locale==='fr'?/Redirections non suivies/:/Redirects not followed/);
  expect(report).toMatch(locale==='fr'?/ni conformité ni efficacité/:/does not establish compliance or effectiveness/);
 });
});
