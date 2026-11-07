import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import DigitalFortress from './views/DigitalFortress';
import {LocaleProvider} from './i18n';
import {readFileSync} from 'node:fs';

it.skipIf(!process.env.SENTINEL_PRIVATE_IMPORT_SAMPLE)('imports an explicitly selected local file without fetch and rejects invalid input',async()=>{
 const sample=process.env.SENTINEL_PRIVATE_IMPORT_SAMPLE!;
 const content=readFileSync(sample,'utf8');
 const fetcher=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('unexpected fetch'));
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 const input=screen.getByLabelText(/fichier de diagnostic|diagnostic file/i);
 fireEvent.change(input,{target:{files:[new File([content],'diagnostic.json',{type:'application/json'})]}});
 const frame=await screen.findByTitle(/aperçu du rapport|report preview/i);
 expect(frame.getAttribute('srcdoc')).toContain(JSON.parse(content).target);
 expect(frame.getAttribute('srcdoc')).toContain(JSON.parse(content).observed_at);
 expect(fetcher).not.toHaveBeenCalled();
 fireEvent.change(input,{target:{files:[new File(['{"secret":"attack"}'],'bad.json',{type:'application/json'})]}});
 await waitFor(()=>expect(screen.getByRole('alert')).toBeInTheDocument());
 expect(screen.queryByTitle(/aperçu du rapport|report preview/i)).not.toBeInTheDocument();
 expect(fetcher).not.toHaveBeenCalled();fetcher.mockRestore();
});
