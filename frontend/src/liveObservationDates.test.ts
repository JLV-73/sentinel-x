import {describe,it,expect} from 'vitest';
import {parseObservation} from './liveObservation';

const input='https://example.org/';
const observation=()=>({mode:'live',target:input,observed_at:'2026-01-01T00:00:00Z',http_status:200,tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3',not_before:'Jan  1 00:00:00 2026 GMT',not_after:'Jan  1 00:00:00 2027 GMT'},headers:{hsts:'present',csp:'absent',x_content_type_options:'present',referrer_policy:'present',permissions_policy:'absent'},failure_code:'none'});

describe('live observation date validation',()=>{
 it.each(['2026-01-01T24:00:00Z','2026-01-01T24:00:00.000000+00:00'])('rejects UTC hour 24: %s',observed_at=>{
  expect(()=>parseObservation({...observation(),observed_at},input)).toThrow();
 });
 it.each(['Feb 31 00:00:00 2026 GMT','Feb 29 12:00:00 2025 GMT','Feb 29 00:00:00 1900 GMT','Apr 31 00:00:00 2026 GMT','Jan  1 24:00:00 2026 GMT','Jan  1 00:00:00 0000 GMT','Jan  1 00:00:60 2026 GMT'])('rejects impossible certificate dates: %s',date=>{
  for(const field of ['not_before','not_after'] as const){const g=observation();expect(()=>parseObservation({...g,tls:{...g.tls,[field]:date}},input)).toThrow();}
 });
 it.each(['Feb 29 12:00:00 2024 GMT','Jan  1 00:00:00 2026 GMT','Sep 30 23:59:59 2026 GMT','Jan 01 00:00:00 2026 GMT'])('accepts real certificate dates: %s',date=>{
  const g=observation();expect(parseObservation({...g,tls:{...g.tls,not_before:date}},input).tls.not_before).toBe(date);
 });
 it.each(['2024-02-29T23:59:59.123456Z','2026-01-01T00:00:00+00:00'])('accepts real UTC instants: %s',observed_at=>{
  expect(parseObservation({...observation(),observed_at},input).observed_at).toBe(observed_at);
 });
});
