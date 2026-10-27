import {useI18n} from '../i18n';
import {useRef,useEffect,useMemo,useState} from 'react';
import * as echarts from 'echarts/core';
import {LineChart,BarChart} from 'echarts/charts';
import {GridComponent,TooltipComponent,AriaComponent} from 'echarts/components';
import {SVGRenderer} from 'echarts/renderers';
import type {EChartsCoreOption} from 'echarts/core';
import {trendOptions,vendorOptions,monthLabel} from '../chartOptions';
echarts.use([LineChart,BarChart,GridComponent,TooltipComponent,AriaComponent,SVGRenderer]);
function useReducedMotion() {
 const [reduced,setReduced]=useState(()=>window.matchMedia?.('(prefers-reduced-motion: reduce)').matches||false);
 useEffect(()=>{const media=window.matchMedia?.('(prefers-reduced-motion: reduce)');if(!media)return;const change=()=>setReduced(media.matches);media.addEventListener('change',change);return()=>media.removeEventListener('change',change);},[]);
 return reduced;
}
function Chart({options,label,height=210,onSelect}:{options:EChartsCoreOption;label:string;height?:number;onSelect?:(vendor:string)=>void}) {
 const container=useRef<HTMLDivElement>(null);
 useEffect(()=>{
  if(!container.current)return;
  const chart=echarts.init(container.current,undefined,{renderer:'svg'});chart.setOption(options);
  if(onSelect)chart.on('click',params=>{if(params.componentType==='series'&&typeof params.name==='string')onSelect(params.name);});
  const resize=()=>chart.resize();
  const observer=typeof ResizeObserver!=='undefined'?new ResizeObserver(resize):null;
  if(observer)observer.observe(container.current);else window.addEventListener('resize',resize);
  return()=>{observer?.disconnect();window.removeEventListener('resize',resize);chart.dispose();};
 },[options,onSelect]);
 return <div ref={container} className="chart" role="img" aria-label={label} style={{height}}/>;
}
export function TrendChart({data}:{data:{period:string;count:number}[]}) {
 const {t,locale,number}=useI18n();const reduced=useReducedMotion();const options=useMemo(()=>trendOptions(data,reduced,locale),[data,reduced,locale]);
 return <div className="trend-chart"><Chart options={options} label={t('chartTrend')}/><table className="sr-only" aria-label={t('monthlyValues')}><thead><tr><th>{t('month')}</th><th>{t('additions')}</th></tr></thead><tbody>{data.map(d=><tr key={d.period}><td>{monthLabel(d.period,locale)}</td><td>{number(d.count)}</td></tr>)}</tbody></table></div>;
}
export function VendorChart({data,onSelect}:{data:{vendor:string;count:number}[];onSelect:(vendor:string)=>void}) {
 const {t,locale,number}=useI18n();const reduced=useReducedMotion();const options=useMemo(()=>vendorOptions(data,reduced,locale),[data,reduced,locale]);
 return <div className="vendor-chart"><Chart options={options} label={t('chartVendors')} height={Math.max(140,data.length*26)} onSelect={onSelect}/><div className="vendor-keyboard" aria-label={t('keyboardVendors')}>{data.map(d=><button key={d.vendor} aria-label={t('filterVendor',{vendor:d.vendor})} onClick={()=>onSelect(d.vendor)}>{d.vendor}<span>{number(d.count)}</span></button>)}</div></div>;
}
