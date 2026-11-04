import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { defaultResponse } from './test/fixtures';

describe('Digital Fortress cockpit introduction', () => {
  afterEach(() => { vi.unstubAllGlobals(); localStorage.removeItem('sentinel-x.locale'); });

  it.each([
    ['fr', 'Laboratoire synthétique local ; les audits de sites Internet réels sont indisponibles.', 'Audit manuel et limité des routes que vous êtes explicitement autorisé à tester.'],
    ['en', 'Local synthetic laboratory; real Internet site audits are unavailable.', 'A manual, bounded audit of routes you are explicitly authorised to test.'],
  ])('clearly describes the local lab in %s', (locale, intro, previous) => {
    localStorage.setItem('sentinel-x.locale', locale);
    window.location.hash = 'fortress';
    vi.stubGlobal('fetch', vi.fn(async (url: string) => defaultResponse(url)));
    render(<App/>);
    expect(screen.queryByText(previous)).not.toBeInTheDocument();
    expect(screen.getByText(intro)).toBeVisible();
  });
});
