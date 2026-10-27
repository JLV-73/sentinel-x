import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import App from './App';
import {defaultResponse,json,record,status} from './test/fixtures';
beforeEach(()=>{window.location.hash='data';vi.stubGlobal('fetch',vi.fn(async (url:string)=>defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it('affiche l’intégrité, l’empreinte, les sources et inspecte le journal des imports',async()=>{
 render(<App/>);
 expect(await screen.findByText('Intégrité vérifiée')).toBeVisible();
 expect(screen.getByText(record.sha256!)).toBeVisible();
 expect(screen.getByRole('button',{name:'Synchroniser maintenant'})).toBeEnabled();
 fireEvent.click(screen.getByRole('button',{name:'Inspecter l’import 1'}));
 expect(await screen.findByRole('heading',{name:'Import #1'})).toBeVisible();
 expect(screen.getAllByText(record.catalog_version!).length).toBeGreaterThan(0);
});
it('journalise l’échec de synchronisation tout en gardant le dernier succès visible',async()=>{
 let posted=false;
 const failed={...record,id:2,status:'failed' as const,error:'Source indisponible',sha256:null,catalog_version:null};
 vi.stubGlobal('fetch',vi.fn(async(url:string,init?:RequestInit)=>{
  if(url==='/api/sync'&&init?.method==='POST'){posted=true;return json({detail:'Source indisponible'},502);}
  if(url==='/api/sync/status'&&posted)return json({...status,last_attempt:failed,history:[failed,record]});
  return defaultResponse(url);
 }));
 render(<App/>);fireEvent.click(await screen.findByRole('button',{name:'Synchroniser maintenant'}));
 expect(await screen.findByText('Échec de la synchronisation')).toBeVisible();
 expect(await screen.findByRole('button',{name:'Inspecter l’import 2'})).toBeVisible();
 expect(screen.getByText(record.sha256!)).toBeVisible();
 expect(screen.getByRole('button',{name:'Synchroniser maintenant'})).toBeEnabled();
});
it('vérifie le succès par relecture du statut et empêche une double soumission',async()=>{
 let release:(r:Response)=>void=()=>{};let posted=false;
 const next={...record,id:3,catalog_version:'2026.10.21'};
 const fetcher=vi.fn((url:string,init?:RequestInit)=>{
  if(url==='/api/sync'&&init?.method==='POST'){posted=true;return new Promise<Response>(resolve=>{release=resolve;});}
  if(url==='/api/sync/status'&&posted)return Promise.resolve(json({...status,last_attempt:next,last_success:next,history:[next,record]}));
  return Promise.resolve(defaultResponse(url));
 });vi.stubGlobal('fetch',fetcher);
 render(<App/>);fireEvent.click(await screen.findByRole('button',{name:'Synchroniser maintenant'}));
 expect(await screen.findByRole('button',{name:'Synchronisation en cours…'})).toBeDisabled();
 release(json(next));
 expect(await screen.findByText('Synchronisation vérifiée')).toBeVisible();
 expect(fetcher.mock.calls.filter(([u])=>u==='/api/sync')).toHaveLength(1);
 expect(screen.getAllByText('2026.10.21').length).toBeGreaterThan(0);
});
it('présente un état vide sans inventer d’import et bloque une synchronisation déjà active',async()=>{
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>url==='/api/sync/status'?json({...status,data_mode:'NO DATA',last_attempt:null,last_success:null,history:[],database:{status:'ok',integrity:'ok',count:0},syncing:true}):defaultResponse(url)));
 render(<App/>);
 expect(await screen.findByText('Aucun import enregistré')).toBeVisible();
 expect(screen.getByRole('button',{name:'Synchronisation en cours…'})).toBeDisabled();
 expect(screen.queryByText(record.sha256!)).not.toBeInTheDocument();
});
