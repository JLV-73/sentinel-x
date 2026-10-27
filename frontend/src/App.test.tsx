import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { beforeEach, afterEach, describe, it, expect, vi } from 'vitest';
import App from './App';
import { summary, json, defaultResponse } from './test/fixtures';
vi.mock('./components/Charts', () => ({TrendChart:()=> <div data-testid="trend-chart"/>,VendorChart:({onSelect}:{onSelect:(v:string)=>void})=> <button onClick={()=>onSelect('Microsoft')}>Graphique Microsoft</button>}));
beforeEach(() => { window.location.hash='overview'; vi.stubGlobal('fetch',vi.fn(async (url:string)=>defaultResponse(url))); });
afterEach(() => vi.unstubAllGlobals());
describe('navigation', () => {
 it('active le lien d’évitement sans quitter le catalogue', async () => {
   window.location.hash='intelligence';
   render(<App/>);
   expect(await screen.findByRole('button',{name:/Ouvrir CVE-2026-1234/})).toBeVisible();
   const skipLink=screen.getByRole('link',{name:'Aller au contenu'});
   skipLink.focus();
   fireEvent.click(skipLink);
   await waitFor(()=>expect(screen.getByRole('main')).toHaveFocus());
   expect(window.location.hash).toBe('#intelligence');
   expect(screen.getByRole('heading',{name:'Renseignement cyber'})).toBeVisible();
   expect(screen.getByRole('button',{name:/Ouvrir CVE-2026-1234/})).toBeVisible();
 });
 it.each(['au chargement','au changement de hash'])('affiche une erreur CVE contrôlée pour un hash malformé %s', async moment => {
   vi.stubGlobal('fetch',vi.fn(async (url:string)=>url==='/api/vulnerabilities/%25'?json({detail:'Identifiant CVE invalide.'},422):defaultResponse(url)));
   if(moment==='au chargement') window.location.hash='cve/%';
   render(<App/>);
   if(moment==='au changement de hash') {
     expect(await screen.findByTestId('metric-total')).toBeVisible();
     window.location.hash='cve/%';
     fireEvent(window,new HashChangeEvent('hashchange'));
   }
   expect(await screen.findByText('Identifiant CVE invalide')).toBeVisible();
   expect(window.location.hash).toBe('#cve/%');
   expect(fetch).toHaveBeenCalledWith('/api/vulnerabilities/%25',expect.any(Object));
   fireEvent.click(screen.getByRole('button',{name:'Retour à la vue d’ensemble'}));
   expect(await screen.findByTestId('metric-total')).toBeVisible();
   expect(window.location.hash).toBe('#overview');
 });
});
describe('poste de veille / vue d’ensemble', () => {
 it('affiche uniquement les métriques API et ouvre une CVE récente', async () => {
   render(<App/>);
   expect(await screen.findByRole('heading',{name:"Vue d'ensemble"})).toBeVisible();
   expect(await screen.findByText('Données réelles')).toBeVisible();
   expect(await screen.findByTestId('metric-total')).toHaveTextContent('2');
   expect(screen.getByTestId('metric-new')).toHaveTextContent('1');
   expect(screen.getByText(/ne déduit aucune vulnérabilité de vos actifs/i)).toBeVisible();
   fireEvent.click(screen.getByRole('button',{name:/Ouvrir CVE-2026-1234/}));
   expect(await screen.findByRole('heading',{name:/Fiche de vulnérabilité.*CVE-2026-1234/})).toBeVisible();
 });
 it('montre NO DATA et une invitation à synchroniser, sans graphique fictif', async () => {
   vi.stubGlobal('fetch',vi.fn(async (url:string)=>url==='/api/summary'?json({...summary,data_mode:'NO DATA',total:0,new_last_30_days:0,ransomware_known:0,vendor_count:0,latest:[],added_by_month:[],top_vendors:[],provenance:null}):defaultResponse(url)));
   render(<App/>);
   expect(await screen.findByText('Aucune donnée')).toBeVisible();
   expect(await screen.findByText('Aucun catalogue importé')).toBeVisible();
   expect(screen.queryByTestId('trend-chart')).not.toBeInTheDocument();
   expect(screen.queryByText('CVE-2026-1234')).not.toBeInTheDocument();
 });
 it('signale le backend hors ligne et propose de réessayer, sans repli de données', async () => {
   vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
   render(<App/>);
   expect(await screen.findByText('Service local indisponible')).toBeVisible();
   expect(screen.queryByTestId('metric-total')).not.toBeInTheDocument();
   expect(screen.getAllByRole('button',{name:/Réessayer/}).length).toBeGreaterThan(0);
 });
});
