import {it, expect} from 'vitest';
import {chromium} from '@playwright/test';
import {existsSync, mkdirSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {renderFortressReport} from './fortressReport';

const fixture = {mode:'fixture',route:'/',target:'https://standard-lab.invalid/',scenario:'ok',failure_code:'none',http_status:200,tls:{certificate:'verified',hostname:'verified',protocol:'TLSv1.3'}};
const imported = {mode:'import',version:1,provenance:'original_sanitized_observations',target:'https://example.org/',observed_at:'2025-01-15T12:00:00+01:00',method:'GET',scope:'root_only',http_status:200,tls:{protocol:'TLSv1.3',certificate:'verified',hostname:'verified',not_before:'2024-12-01T00:00:00Z',not_after:'2025-12-01T00:00:00Z',revocation:'not_checked'},headers:{hsts:{state:'present',max_age_seconds:31536000,include_subdomains:true},csp:{state:'present',unsafe_inline:true,wildcard:true,location:'unknown'},referrer_policy:'strict-origin-when-cross-origin',x_content_type_options:'nosniff',permissions_policy:'absent'},cookies:{count:1,secure:1,httponly:1,samesite_absent:1}};

const executablePath = process.env.SENTINEL_CHROMIUM || chromium.executablePath();
it.skipIf(!existsSync(executablePath))('keeps TLS label words intact on desktop and avoids overflow on desktop and mobile', async () => {
 const output = process.env.SENTINEL_LAYOUT_OUTPUT;
 if (output) mkdirSync(output, {recursive:true});
 const browser = await chromium.launch({executablePath, headless:true, args:['--disable-background-networking','--disable-component-update','--disable-sync','--no-first-run','--host-resolver-rules=MAP * ~NOTFOUND','--proxy-server=http://127.0.0.1:9','--proxy-bypass-list=<-loopback>']});
 const results: unknown[] = [];
 const failures: string[] = [];
 try {
  for (const [kind, data] of [['fixture',fixture],['import',imported]] as const) for (const locale of ['fr','en'] as const) for (const [device,width,height] of [['desktop',1440,900],['mobile',390,844]] as const) {
   const context = await browser.newContext({viewport:{width,height}, serviceWorkers:'block'});
   await context.route('**/*', route => route.abort());
   const page = await context.newPage();
   await page.setContent(renderFortressReport(data,locale));
   const measurement = await page.evaluate(({locale}) => {
    const wanted = locale === 'fr' ? ['Certificat','Nom d’hôte'] : ['Certificate','Hostname'];
    const spans = [...document.querySelectorAll('.row span')];
    const labels = wanted.map(label => {
     const el = spans.find(e => e.textContent === label);
     if (!el || !el.firstChild) throw Error('Missing label: '+label);
     const node = el.firstChild;
     const words = [...label.matchAll(/\S+/g)].map(match => {
      const r = document.createRange(); r.setStart(node,match.index!); r.setEnd(node,match.index!+match[0].length);
      return {word:match[0],rects:[...r.getClientRects()].map(r=>({x:r.x,y:r.y,width:r.width,height:r.height}))};
     });
     const box=el.getBoundingClientRect();
     return {label,width:box.width,height:box.height,words};
    });
    const overflows=[...document.querySelectorAll('body, main, .grid, .box, .row, .row span, .row strong')].filter(e=>e.scrollWidth>e.clientWidth+1).map(e=>({tag:e.tagName,className:e.className,text:e.textContent?.slice(0,80),scroll:e.scrollWidth,client:e.clientWidth}));
    return {viewport:innerWidth,documentWidth:document.documentElement.scrollWidth,labels,overflows};
   },{locale});
   const record={kind,locale,device,...measurement}; results.push(record);
   if (output) await page.screenshot({path:join(output,`${kind}-${locale}-${device}.png`),fullPage:true});
   for (const label of measurement.labels) for(const word of label.words) if (word.rects.length !== 1) failures.push(`${kind}/${locale}/${device}: ${word.word} split into ${word.rects.length} fragments`);
   if (measurement.documentWidth>width || measurement.overflows.length) failures.push(`${kind}/${locale}/${device}: horizontal overflow ${JSON.stringify(measurement.overflows)}`);
   await context.close();
  }
 } finally { await browser.close(); if(output) writeFileSync(join(output,'measurements.json'),JSON.stringify({results,failures},null,2)); }
 expect(failures, JSON.stringify(failures,null,2)).toEqual([]);
}, 120000);
