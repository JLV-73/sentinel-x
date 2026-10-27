import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import App from './App';
import {defaultResponse,json,vuln} from './test/fixtures';
beforeEach(()=>{window.location.hash='intelligence';vi.stubGlobal('fetch',vi.fn(async (url:string)=>defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it('recherche CVE/éditeur/produit avec debounce, sélection exacte et filtres serveur',async()=>{
 render(<App/>);
 const input=await screen.findByRole('searchbox',{name:'Rechercher une CVE, un éditeur ou un produit'});
 fireEvent.change(input,{target:{value:'CVE-2026'}});
 expect((fetch as ReturnType<typeof vi.fn>).mock.calls.some(([u])=>String(u).includes('q=CVE-2026'))).toBe(false);
 await waitFor(()=>expect((fetch as ReturnType<typeof vi.fn>).mock.calls.some(([u])=>String(u).includes('q=CVE-2026'))).toBe(true));
 await screen.findByRole('option',{name:'Microsoft'});
 fireEvent.change(screen.getByLabelText('Éditeur exact'),{target:{value:'Microsoft'}});
 fireEvent.change(screen.getByLabelText('Usage rançongiciel'),{target:{value:'Known'}});
 fireEvent.change(screen.getByLabelText('Ordre des ajouts'),{target:{value:'asc'}});
 await waitFor(()=>expect((fetch as ReturnType<typeof vi.fn>).mock.calls.some(([u])=>String(u).includes('vendor=Microsoft')&&String(u).includes('ransomware=Known')&&String(u).includes('sort=asc'))).toBe(true));
 fireEvent.click(screen.getByRole('button',{name:'Réinitialiser les filtres'}));
 expect(input).toHaveValue('');
});
it('pagine et conserve les filtres après inspection puis retour',async()=>{
 vi.stubGlobal('fetch',vi.fn(async (url:string)=>{
  if(url.startsWith('/api/vulnerabilities?')&&url.includes('page_size=20')) {const p=Number(new URL(url,'http://localhost').searchParams.get('page'));return json({items:[vuln],total:41,page:p,page_size:20,pages:3});}return defaultResponse(url);
 }));
 render(<App/>);
 fireEvent.change(await screen.findByRole('searchbox'),{target:{value:'Microsoft'}});
 await waitFor(()=>expect((fetch as ReturnType<typeof vi.fn>).mock.calls.some(([u])=>String(u).includes('q=Microsoft'))).toBe(true));
 fireEvent.click(await screen.findByRole('button',{name:'Page suivante'}));
 expect(await screen.findByText('Page 2 sur 3')).toBeVisible();
 fireEvent.click(await screen.findByRole('button',{name:'Ouvrir CVE-2026-1234'}));
 fireEvent.click(await screen.findByRole('button',{name:'Retour au catalogue'}));
 expect(await screen.findByRole('searchbox')).toHaveValue('Microsoft');
 expect(await screen.findByText('Page 2 sur 3')).toBeVisible();
});
it('ignore une réponse ancienne même si le transport ne respecte pas abort',async()=>{
 let resolveOld:(r:Response)=>void=()=>{};
 vi.stubGlobal('fetch',vi.fn((url:string)=>{
  const q=new URL(url,'http://localhost').searchParams.get('q');
  if(q==='ancien') return new Promise<Response>(resolve=>{resolveOld=resolve;});
  if(q==='récent') return Promise.resolve(json({items:[{...vuln,cveID:'CVE-2026-9999'}],total:1,page:1,page_size:20,pages:1}));
  return Promise.resolve(defaultResponse(url));
 }));
 render(<App/>);const input=await screen.findByRole('searchbox');
 fireEvent.change(input,{target:{value:'ancien'}});
 await waitFor(()=>expect((fetch as ReturnType<typeof vi.fn>).mock.calls.some(([u])=>String(u).includes('q=ancien'))).toBe(true));
 const oldCall=(fetch as ReturnType<typeof vi.fn>).mock.calls.find(([u])=>String(u).includes('q=ancien'))!;
 fireEvent.change(input,{target:{value:'récent'}});
 expect(await screen.findByRole('button',{name:'Ouvrir CVE-2026-9999'})).toBeVisible();
 expect(oldCall[1].signal.aborted).toBe(true);
 resolveOld(json({items:[vuln],total:1,page:1,page_size:20,pages:1}));
 await waitFor(()=>expect(screen.queryByRole('button',{name:'Ouvrir CVE-2026-1234'})).not.toBeInTheDocument());
});
it('distingue une recherche vide et une erreur HTTP',async()=>{
 vi.stubGlobal('fetch',vi.fn(async (url:string)=>url.includes('page_size=20')?json({items:[],total:0,page:1,page_size:20,pages:0}):defaultResponse(url)));
 render(<App/>);expect(await screen.findByText('Aucune entrée correspondante')).toBeVisible();
});
