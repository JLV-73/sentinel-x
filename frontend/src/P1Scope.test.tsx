import {render,screen} from '@testing-library/react';
import {beforeEach,afterEach,it,expect,vi} from 'vitest';
import App from './App';
import {defaultResponse} from './test/fixtures';
beforeEach(()=>{window.location.hash='data';localStorage.setItem('sentinel-x.locale','en');vi.stubGlobal('fetch',vi.fn(async(url:string)=>defaultResponse(url)));});
afterEach(()=>vi.unstubAllGlobals());
it('scopes CISA policy without denying independent NVD/FIRST enrichment',async()=>{
 render(<App/>);
 expect(await screen.findByText('This CISA import uses the canonical KEV feed, with the official mirror as fallback. NVD and FIRST enrichments are separate sources, shown independently below.')).toBeVisible();
 expect(screen.queryByText(/No third-party services or enriched scores/)).not.toBeInTheDocument();
});
