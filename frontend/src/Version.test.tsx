import { readFileSync } from 'node:fs';
import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { defaultResponse } from './test/fixtures';

const version = readFileSync('../VERSION', 'utf8').trim();
vi.mock('./components/Charts', () => ({TrendChart:()=> <div data-testid="trend-chart"/>,VendorChart:()=> <div/>}));
beforeEach(() => { window.location.hash='overview'; vi.stubGlobal('fetch',vi.fn(async (url:string)=>defaultResponse(url))); });
afterEach(() => vi.unstubAllGlobals());

describe('cockpit version', () => {
 it('keeps npm package and root lock metadata aligned with VERSION', () => {
   const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
   const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
   expect(pkg.version).toBe(version);
   expect(lock.version).toBe(version);
   expect(lock.packages[''].version).toBe(version);
 });
 it.each(['fr','en'] as const)('renders the exact root VERSION badge in %s', async locale => {
   localStorage.setItem('sentinel-x.locale',locale);
   const { container } = render(<App/>);
   expect(await screen.findByTestId('metric-total')).toBeVisible();
   expect(screen.getByTestId(`language-${locale}`)).toHaveAttribute('aria-pressed','true');
   const badge = container.querySelector('.sidebar-foot > span:last-child');
   expect(badge).toBeVisible();
   expect(badge?.textContent).toBe(`v${version}`);
 });
});
