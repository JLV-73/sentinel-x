import {it,expect} from 'vitest';
import {renderFortressReport} from './fortressReport';

it('separates reported classifications, evidence and recommendations in a bilingual collapsible report',()=>{
 const input={complete:false,requests_used:1,findings:[{id:'hsts',status:'attention',severity:'low',evidence_code:'header_absent'},{id:'csp',status:'indeterminate',severity:'unknown'}]};
 for(const [locale,overview,details,evidence,recommendations] of [['fr','Synthèse des classifications transmises','Détails des constats','Éléments de preuve','Correction'],['en','Reported classification overview','Finding details','Evidence','Remedy']] as const){
  const doc=new DOMParser().parseFromString(renderFortressReport(input,locale),'text/html');
  expect(doc.body.textContent).toContain(overview);
  const panel=[...doc.querySelectorAll('details')].find(x=>x.querySelector('summary')?.textContent===details);
  expect(panel).toBeDefined();expect(panel?.hasAttribute('open')).toBe(false);
  expect(panel?.textContent).toContain(evidence);expect(panel?.textContent).toContain(recommendations);
  expect(doc.body.textContent).toContain(locale==='fr'?'non effectués restent indéterminés':'unperformed checks remain indeterminate');
 }
});
