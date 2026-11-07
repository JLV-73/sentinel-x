import {describe,it,expect} from 'vitest';
import {renderFortressReport} from './fortressReport';

describe('local fixture report',()=>{
 it('does not treat arbitrary JSON as verified TLS',()=>{
  const html=renderFortressReport({tls:{certificate:'verified',hostname:'verified'},payload:'<script>alert(1)</script>'},'en');
  expect(html).toContain('indeterminate');
  expect(html).not.toContain('<script>alert(1)</script>');
  expect(html).not.toContain('TLS certificate: verified');
 });
});
