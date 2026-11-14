import {useId,useState} from 'react';
import {useI18n} from '../i18n';
import {adaptDiscoveryLab} from '../discoveryLabAdapter';
import {renderDiscoveryReport} from '../discoveryReport';
import {discoveryDemoFixture} from '../discoveryDemoFixture';
import './DiscoveryDemo.css';

export default function DiscoveryDemo(){
 const {locale}=useI18n();
 const fr=locale==='fr';
 const [visible,setVisible]=useState(false);
 const panelId=useId();
 const html=visible?renderDiscoveryReport(adaptDiscoveryLab(discoveryDemoFixture),locale):'';
 const download=()=>{
  if(!html)return;
  const url=URL.createObjectURL(new Blob([html],{type:'text/html;charset=utf-8'}));
  const a=document.createElement('a');a.href=url;a.download=`discovery-synthetic-${locale}.html`;a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
 };
 return <section className="panel fortress-panel discovery-demo" aria-label={fr?'Discovery synthétique':'Discovery synthetic'}>
  <p className="fortress-kicker">DISCOVERY / SYNTHETIC / LOCAL</p>
  <h2>{fr?'Discovery — démonstration synthétique':'Discovery — synthetic demonstration'}</h2>
  <p>{fr?'Données entièrement fictives : aucune observation de terrain. Consulte le statut du mode réel dans le volet Exploration autorisée. Aucun réseau, aucune cible et aucune requête dans ce volet.':'Entirely fictional data: no field observation. See the live mode status in the Authorized exploration panel. No network, target, or requests in this panel.'}</p>
  <button type="button" className="button" aria-expanded={visible} aria-controls={panelId} onClick={()=>setVisible(value=>!value)}>{visible?(fr?'Masquer le rapport synthétique':'Hide synthetic report'):(fr?'Voir le rapport synthétique':'View synthetic report')}</button>
  <div id={panelId} hidden={!visible}>{visible&&<><button type="button" className="button" onClick={download}>{fr?'Télécharger le rapport synthétique':'Download synthetic report'} · {locale.toUpperCase()}</button><iframe title={fr?'Aperçu Discovery synthétique':'Discovery synthetic preview'} className="fortress-preview" sandbox="" srcDoc={html}/></>}</div>
 </section>;
}
