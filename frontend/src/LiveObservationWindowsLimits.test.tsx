import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,render,screen} from '@testing-library/react';
import LiveObservation from './components/LiveObservation';
import {LocaleProvider,localeKey} from './i18n';

afterEach(()=>{cleanup();localStorage.removeItem(localeKey);vi.restoreAllMocks();});

it.each([
 ['fr','Supervision Windows expérimentale : en cas de défaillance native, la terminaison de tous les descendants n’est pas garantie.','L’exclusion entre tous les comptes et sessions Windows n’est pas qualifiée.','Modifier ou fermer cette vue ne garantit pas l’annulation d’une requête déjà engagée.','Observer le site'],
 ['en','Windows supervision is experimental: if a native failure occurs, termination of all descendants is not guaranteed.','Exclusion across all Windows accounts and sessions is not qualified.','Changing or closing this view does not guarantee cancellation of an already started request.','Observe site'],
])('shows Windows and cancellation limits before activation in %s',(locale,supervision,exclusion,cancellation,buttonName)=>{
 localStorage.setItem(localeKey,locale);
 const fetcher=vi.spyOn(globalThis,'fetch');
 render(<LocaleProvider><LiveObservation/></LocaleProvider>);
 for(const text of [supervision,exclusion,cancellation])expect(screen.getByText(text)).toBeVisible();
 expect(screen.getByRole('button',{name:buttonName})).toBeDisabled();
 expect(fetcher).not.toHaveBeenCalled();
});
