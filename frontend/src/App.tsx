import { useState, useEffect, useRef } from 'react';
import { Activity, ArrowLeft, Database, LayoutDashboard, Radio, Shield, Terminal, RefreshCw } from 'lucide-react';
import { api } from './api';
import { useApi, useHash } from './hooks';
import { Loading, ErrorState } from './components/UI';
import Overview from './views/Overview';
import Catalogue from './views/Catalogue';
import Detail from './views/Detail';
import DataControl from './views/DataControl';
import { ApiError } from './api';
import type { CatalogueFilters } from './types';
export const initialFilters:CatalogueFilters={q:'',vendor:'',ransomware:'',sort:'desc',page:1,page_size:20};
import {LocaleProvider,LanguageSwitch,useI18n} from './i18n';
export default function App(){return <LocaleProvider><AppContent/></LocaleProvider>;}
function AppContent() {
 const {t,date}=useI18n();
 const [route,navigate]=useHash(); const [revision,setRevision]=useState(0);
 const [filters,setFilters]=useState<CatalogueFilters>(initialFilters);
 const [detailBack,setDetailBack]=useState('overview');
 const summary=useApi(signal=>api.summary(signal),`summary-${revision}`);
 const health=useApi(signal=>api.health(signal),`health-${revision}`);
 const detailId=route.startsWith('cve/')?route.slice(4):null;
 const detail=useApi(signal=>detailId?api.detail(detailId,signal):Promise.resolve(null),`detail-${detailId}-${revision}`);
 const page=detailId?'detail':route==='intelligence'?'intelligence':route==='data'?'data':'overview';
 const titles={overview:t('overview'),intelligence:t('intelligence'),data:t('dataControl'),detail:t('detail')};
 const heading=useRef<HTMLHeadingElement>(null); const mounted=useRef(false);
 useEffect(()=>{if(mounted.current) heading.current?.focus();mounted.current=true;},[route]);
 const open=(id:string)=>{setDetailBack(page==='intelligence'?'intelligence':'overview');navigate(`cve/${id}`);};
 const catalogue=(vendor='')=>{setFilters({...initialFilters,vendor});navigate('intelligence');};
 const mode=summary.data?.data_mode;
 return <div className="app-shell"><a className="skip-link" href="#main-content" onClick={event=>{event.preventDefault();document.getElementById('main-content')?.focus();}}>{t('skip')}</a><aside className="sidebar"><a className="brand" href="#overview" aria-label={t('home')}><span className="brand-symbol"><Shield size={25}/><span>X</span></span><span>SENTINEL<span className="brand-x">X</span><small>NIGHTFALL / INTELLIGENCE</small></span></a><div className="workspace-label"><span className="status-dot"/>{t('station')}</div><nav aria-label={t('navigation')}><span className="nav-group">{t('observation')}</span><a href="#overview" className={page==='overview'?'active':''} aria-current={page==='overview'?'page':undefined}><LayoutDashboard size={17}/><span>{t('overview')}</span><span className="nav-number">01</span></a><a href="#intelligence" className={page==='intelligence'||page==='detail'?'active':''} aria-current={page==='intelligence'?'page':undefined}><RadarIcon/><span>{t('intelligence')}</span><span className="nav-number">02</span></a><span className="nav-group nav-group-second">{t('system')}</span><a href="#data" className={page==='data'?'active':''} aria-current={page==='data'?'page':undefined}><Database size={17}/><span>{t('dataControl')}</span><span className="nav-number">03</span></a></nav><div className="sidebar-bottom"><div className="local-system"><Terminal size={17}/><div><strong>{t('instance')}</strong><span>{t('localKev')}</span></div><span className={`status-dot ${health.error?'dot-error':''}`}/></div><div className="sidebar-foot"><span>{t('edition')}</span><span>v1.0</span></div></div></aside><div className="main-shell"><header className="topbar"><div className="breadcrumb">{t('workspace')}<span>/</span><strong>{page==='data'?t('crumbData'):page==='detail'?t('crumbDetail'):page==='intelligence'?t('crumbIntelligence'):t('crumbOverview')}</strong></div><div className="connection"><span className={`status-dot ${health.error?'dot-error':''}`}/><span>{health.loading?t('connecting'):health.error?t('offline'):t('backend')}</span><span className="topbar-divider"/><span>CISA / KEV</span><LanguageSwitch/></div></header><main id="main-content" tabIndex={-1}><div className="page-heading"><div><div className="eyebrow"><span className="micro-cross">+</span>{page==='data'?t('integrityProvenance'):page==='detail'?t('officialEntry'):t('monitor')}</div><h1 ref={heading} tabIndex={-1}>{titles[page]}{detailId&&<span className="detail-heading-id mono">{detailId}</span>}</h1><p>{page==='overview'?t('overviewIntro'):page==='intelligence'?t('catalogueIntro'):page==='data'?t('dataIntro'):t('detailIntro')}</p></div><div className="heading-actions">{mode&&<span className={`mode-badge ${mode==='REAL DATA'?'real':''}`} data-mode={mode} title={mode}><span className="status-dot"/>{mode==='REAL DATA'?t('realData'):mode==='NO DATA'?t('noData'):mode}</span>}<button className="button" onClick={()=>navigate('data')}><RefreshCw size={14}/>{t('sync')}</button></div></div>{page==='overview'&&(summary.loading?<Loading/>:summary.error?<ErrorState error={summary.error} retry={()=>setRevision(v=>v+1)}/>:summary.data?<Overview data={summary.data} open={open} catalogue={catalogue} control={()=>navigate('data')}/>:null)}{page==='detail'&&<><button className="text-button back-link" onClick={()=>navigate(detailBack)}><ArrowLeft size={15}/>{t(detailBack==='overview'?'backOverview':'backCatalogue')}</button>{detail.loading?<Loading label={t('loadingDetail')}/>:detail.error?<ErrorState error={detail.error} title={detail.error instanceof ApiError&&detail.error.status===404?t('notFound'):detail.error instanceof ApiError&&detail.error.status===422?t('invalidCve'):t('detailUnavailable')} retry={()=>setRevision(v=>v+1)}/>:detail.data?<Detail data={detail.data}/>:null}</>}{page==='intelligence'&&<Catalogue filters={filters} setFilters={setFilters} open={open} revision={revision}/>}{page==='data'&&<DataControl revision={revision} onUpdated={()=>setRevision(v=>v+1)}/>}<footer className="app-footer"><span><Radio size={12}/>{t('officialSources')}</span><span>{summary.data?t('consulted',{date:date(summary.data.as_of_utc,true)}):t('noLoaded')}<i/>{t('localRead')}</span></footer></main></div></div>;
}
function RadarIcon(){return <Activity size={17}/>;}
