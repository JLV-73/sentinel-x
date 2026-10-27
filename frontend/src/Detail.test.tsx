import {render,screen} from '@testing-library/react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import App from './App';
import {defaultResponse,json,vuln,record} from './test/fixtures';
beforeEach(()=>{window.location.hash='cve/CVE-2026-1234';vi.stubGlobal('fetch',vi.fn(async (url:string)=>defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it('présente les champs officiels, la provenance et la portée de l’échéance CISA',async()=>{
 render(<App/>);
 expect(await screen.findByText(vuln.shortDescription)).toBeVisible();
 expect(screen.getByText(vuln.requiredAction)).toBeVisible();
 expect(screen.getByText('CWE-79')).toBeVisible();
 expect(screen.getByText(/ne constitue pas une obligation réglementaire française/i)).toBeVisible();
 expect(screen.getByText(record.sha256!)).toBeVisible();
 expect(screen.getByRole('link',{name:'Consulter la fiche CVE'})).toHaveAttribute('href','https://www.cve.org/CVERecord?id=CVE-2026-1234');
 expect(screen.getByText('Usage connu')).toBeVisible();
});
it('accepte les champs CISA optionnels absents sans inférer leur valeur',async()=>{
 const optional={...vuln};delete optional.notes;delete optional.knownRansomwareCampaignUse;delete optional.cwes;
 vi.stubGlobal('fetch',vi.fn(async (url:string)=>url.startsWith('/api/vulnerabilities/')?json({vulnerability:optional,provenance:record}):defaultResponse(url)));
 render(<App/>);
 expect(await screen.findByText('Aucune note publiée.')).toBeVisible();
 expect(screen.getAllByText('Non renseigné').length).toBeGreaterThan(0);
 expect(screen.queryByText('Usage connu')).not.toBeInTheDocument();
});
it.each([[404,'CVE introuvable'],[422,'Identifiant CVE invalide']])('distingue une erreur de fiche HTTP %s',async(code,label)=>{
 vi.stubGlobal('fetch',vi.fn(async (url:string)=>url.startsWith('/api/vulnerabilities/')?json({detail:'Erreur de test'},code):defaultResponse(url)));
 render(<App/>);expect(await screen.findByText(label)).toBeVisible();
 expect(screen.queryByText(vuln.shortDescription)).not.toBeInTheDocument();
});
