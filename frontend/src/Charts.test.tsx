import {render,screen,fireEvent} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {trendOptions,vendorOptions} from './chartOptions';
import {LocaleProvider,LanguageSwitch} from './i18n';
import {VendorChart,TrendChart} from './components/Charts';
const mocks=vi.hoisted(()=>({setOption:vi.fn(),on:vi.fn(),dispose:vi.fn(),resize:vi.fn()}));
vi.mock('echarts/core',()=>({use:vi.fn(),init:()=>mocks}));
describe('graphiques fondés uniquement sur les agrégats API',()=>{
 it('conserve les dates et compteurs mensuels, sans les présenter comme des attaques',()=>{
  const option=trendOptions([{period:'2026-09',count:7},{period:'2026-10',count:11}],true);
  expect(option.xAxis.data).toEqual(['2026-09','2026-10']);
  expect(option.series[0].data).toEqual([7,11]);expect(option.series[1].data).toEqual([7,11]);
  expect(option.series[0].name).toBe('Ajouts au catalogue');expect(option.animation).toBe(false);
 });
 it('conserve les noms exacts des éditeurs et sécurise le rendu du tooltip',()=>{
  const option=vendorOptions([{vendor:'Acme & Co',count:4}]);
  expect(option.yAxis.data).toEqual(['Acme & Co']);expect(option.series[0].data).toEqual([4]);
  expect(option.tooltip.renderMode).toBe('richText');
 });
 it('offre un équivalent clavier pour les filtres des barres',()=>{
  const select=vi.fn();render(<VendorChart data={[{vendor:'Acme & Co',count:4}]} onSelect={select}/>);
  fireEvent.click(screen.getByRole('button',{name:'Filtrer sur Acme & Co'}));expect(select).toHaveBeenCalledWith('Acme & Co');
 });
 it('expose les valeurs mensuelles aux lecteurs d’écran',()=>{
  render(<TrendChart data={[{period:'2026-09',count:7}]}/>);
  expect(screen.getByRole('img',{name:/Ajouts mensuels au catalogue/})).toBeInTheDocument();
  expect(screen.getByRole('table',{name:'Valeurs mensuelles du catalogue'})).toHaveTextContent('7');
 });
});

it('localizes chart series, ticks, tooltips and full ARIA descriptions without changing source values',()=>{
 const trend=trendOptions([{period:'2026-10',count:12345}],true,'en');
 expect(trend.series[0].name).toBe('Catalogue additions');expect(trend.xAxis.axisLabel.formatter('2026-10')).toBe('Oct 26');expect(trend.yAxis.axisLabel.formatter(12345)).toBe('12,345');
 expect(trend.tooltip.formatter([{axisValue:'2026-10',value:12345}])).toContain('12,345');expect(trend.aria.label.description).toContain('not attacks');
 const vendor=vendorOptions([{vendor:'Acme & Co',count:12345}],true,'en');expect(vendor.series[0].name).toBe('Catalogue entries');expect(vendor.tooltip.formatter({name:'Acme & Co',value:12345})).toContain('Acme & Co');expect(vendor.aria.label.description).toContain('12,345');expect(vendor.yAxis.data).toEqual(['Acme & Co']);
});

it('updates visible chart options and accessibility labels on a live language switch',()=>{
 render(<LocaleProvider><LanguageSwitch/><TrendChart data={[{period:'2026-10',count:12345}]}/><VendorChart data={[{vendor:'Acme & Co',count:12345}]} onSelect={()=>{}}/></LocaleProvider>);
 expect(screen.getByRole('table',{name:'Valeurs mensuelles du catalogue'})).toHaveTextContent('oct. 26');fireEvent.click(screen.getByTestId('language-en'));
 expect(screen.getByRole('table',{name:'Monthly catalogue values'})).toHaveTextContent('Oct 26');expect(screen.getByRole('table',{name:'Monthly catalogue values'})).toHaveTextContent('12,345');expect(screen.getByRole('img',{name:/Monthly CISA KEV/})).toBeVisible();expect(screen.getByRole('button',{name:'Filter by Acme & Co'})).toHaveTextContent('12,345');
 expect(mocks.setOption.mock.calls.at(-1)?.[0].series[0].name).toBe('Catalogue entries');
});
