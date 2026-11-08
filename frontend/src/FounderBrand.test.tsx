import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {render,screen,waitFor} from '@testing-library/react';
import App from './App';
import {defaultResponse} from './test/fixtures';
vi.mock('./components/Charts',()=>({TrendChart:()=>null,VendorChart:()=>null}));
beforeEach(()=>{localStorage.clear();vi.stubGlobal('fetch',vi.fn(async(url:string)=>defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
const credit='Created by Jean-Louis VIRETTI — JLV Labs';
const legal='© 2026 JLV Labs — Jean-Louis VIRETTI | SENTINEL X — NIGHTFALL | Apache 2.0';
describe('founder identity',()=>{
 it.each(['fr','en'])('shows founder on the home screen in %s',async locale=>{
  localStorage.setItem('sentinel-x.locale',locale);window.location.hash='overview';render(<App/>);
  await screen.findByRole('heading',{level:1});expect(screen.getByText(credit)).toBeVisible();expect(screen.getByText(legal)).toBeVisible();
 });
 it.each([
  ['fr','overview',"Vue d'ensemble"],['en','overview','Overview'],
  ['fr','intelligence','Renseignement cyber'],['en','intelligence','Threat Intelligence'],
  ['fr','triage','Triage du renseignement'],['en','triage','Intelligence Triage'],
  ['fr','fortress','DIGITAL FORTRESS'],['en','fortress','DIGITAL FORTRESS'],
  ['fr','data','Contrôle des données'],['en','data','Data Control'],
  ['fr','cve/CVE-2024-1234','Fiche de vulnérabilité'],['en','cve/CVE-2024-1234','CVE Inspector'],
 ])('shows the footer on %s / %s',async (locale,route,title)=>{
  localStorage.setItem('sentinel-x.locale',locale);window.location.hash=route;render(<App/>);
  await waitFor(()=>expect(screen.getByRole('heading',{level:1})).toHaveTextContent(title));
  expect(screen.getByText(legal)).toBeVisible();
 });
});
