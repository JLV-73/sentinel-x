import {createContext,useContext,useEffect,useState,type ReactNode} from 'react';
export type Locale='fr'|'en';
export const localeKey='sentinel-x.locale';
import {en,fr,type TranslationKey} from './translations';
export {en,fr,type TranslationKey} from './translations';
export const dictionaries:Record<Locale,Record<TranslationKey,string>>={en,fr};
export type Params=Record<string,string|number>;
export function translate(locale:Locale,key:TranslationKey,params:Params={}) {return dictionaries[locale][key].replace(/\{(\w+)\}/g,(_,name:string)=>String(params[name]??`{${name}}`));}
export function initialLocale():Locale {
 try {const stored=window.localStorage.getItem(localeKey);if(stored==='fr'||stored==='en')return stored;} catch {/* Storage may be denied; keep the preference in React memory. */}
 return /^fr(?:-|$)/i.test(navigator.language)?'fr':'en';
}
const LocaleContext=createContext<{locale:Locale;setLocale:(locale:Locale)=>void}>({locale:'fr',setLocale:()=>{}});
export function LocaleProvider({children}:{children:ReactNode}) {
 const [locale,update]=useState<Locale>(initialLocale);
 const setLocale=(next:Locale)=>{if(next!=='fr'&&next!=='en')return;update(next);try {window.localStorage.setItem(localeKey,next);}catch {/* In-memory switching still works. */}};
 useEffect(()=>{document.documentElement.lang=locale;document.title=translate(locale,'title');},[locale]);
 return <LocaleContext.Provider value={{locale,setLocale}}>{children}</LocaleContext.Provider>;
}
export const intlLocale=(locale:Locale)=>({fr:'fr-FR',en:'en-GB'}[locale]);
export function formatNumber(value:number,locale:Locale='fr'){return new Intl.NumberFormat(intlLocale(locale)).format(value);}
export function formatDate(value:string|null|undefined,time=false,locale:Locale='fr'){
 if(!value)return translate(locale,'unavailable');
 const dateOnly=/^\d{4}-\d{2}-\d{2}$/.test(value);
 const d=new Date(dateOnly?`${value}T00:00:00Z`:value);
 if(Number.isNaN(d.getTime()))return translate(locale,'invalidDate');
 return new Intl.DateTimeFormat(intlLocale(locale),{day:'2-digit',month:'short',year:'numeric',...(dateOnly||!time?{timeZone:'UTC'}:{}),...(time&&!dateOnly?{hour:'2-digit',minute:'2-digit',timeZoneName:'short'}:{})}).format(d);
}
export function useI18n(){const context=useContext(LocaleContext);return {...context,t:(key:TranslationKey,params?:Params)=>translate(context.locale,key,params),number:(value:number)=>formatNumber(value,context.locale),date:(value:string|null|undefined,time=false)=>formatDate(value,time,context.locale)};}
export function LanguageSwitch(){const {locale,setLocale,t}=useI18n();return <div className="language-switch" role="group" aria-label={t('language')}><button data-testid="language-fr" type="button" lang="fr" aria-label="Français" aria-pressed={locale==='fr'} onClick={()=>setLocale('fr')}>FR</button><button data-testid="language-en" type="button" lang="en" aria-label="English" aria-pressed={locale==='en'} onClick={()=>setLocale('en')}>EN</button></div>;}
