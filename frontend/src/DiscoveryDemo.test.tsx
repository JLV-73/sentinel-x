import {it, expect, vi} from 'vitest';
import {render, screen, within, fireEvent} from '@testing-library/react';
import DigitalFortress from './views/DigitalFortress';
import {LocaleProvider} from './i18n';

it('offers a clearly synthetic local Discovery preview without sending requests', () => {
 const fetcher=vi.spyOn(globalThis,'fetch');
 render(<LocaleProvider><DigitalFortress/></LocaleProvider>);
 const demo=screen.getByRole('region',{name:/discovery.*synthetic|discovery.*synthétique/i});
 expect(within(demo).getByText(/no field observation|aucune observation de terrain/i)).toBeInTheDocument();
 expect(within(demo).queryAllByRole('textbox')).toHaveLength(0);
 fireEvent.click(within(demo).getByRole('button',{name:/view|voir/i}));
 const frame=within(demo).getByTitle(/discovery.*preview|aperçu.*discovery/i);
 expect(frame).toHaveAttribute('sandbox','');
 expect(frame.getAttribute('srcdoc')).toMatch(/synthetic data|données synthétiques/i);
 expect(fetcher).not.toHaveBeenCalled();
});
