"""Isolated standard lab contract; never contacts a public site."""
import importlib.util
import http.client
import json
import re
import subprocess
import sys
from urllib.parse import urlsplit
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_scenario_uses_real_fixture_and_service_rules():
    path = ROOT / 'scripts' / 'fortress_standard_lab_server.py'
    assert path.is_file(), 'isolated standard lab entrypoint not implemented'
    spec = importlib.util.spec_from_file_location('standard_lab_server', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.run_scenario('negative')
    findings = {f['id']: f['status'] for f in result['findings']}
    assert result['requests_used'] == 1
    assert findings['cookie_attributes'] == 'attention'
    hsts = next(f for f in result['findings'] if f['id'] == 'hsts')
    assert (hsts['status'], hsts['severity'], hsts['evidence_code'], hsts['method'], hsts['route_index'], hsts['route']) == ('attention', 'low', 'header_absent', 'GET', 1, '[redacted route]')
    tls = next(f for f in result['findings'] if f['id'] == 'https_tls')
    assert (tls['status'], tls['severity'], tls['evidence_code']) == ('conformant', 'info', 'tls_verified')
    assert result['route_execution'] == [{'route_index': 1, 'state': 'completed'}]
    assert 'lab-cookie' not in str(result)


def test_fixed_scenarios_only_loopback_and_indeterminate(monkeypatch):
    path = ROOT / 'scripts' / 'fortress_standard_lab_server.py'
    spec = importlib.util.spec_from_file_location('standard_lab_server_scenarios', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import socket
    original_connect = socket.socket.connect
    addresses = []
    def only_loopback(sock, address):
        assert address[0] == '127.0.0.1'
        addresses.append(address)
        return original_connect(sock, address)
    def no_dns(*args, **kwargs):
        raise AssertionError('real DNS forbidden')
    monkeypatch.setattr(socket.socket, 'connect', only_loopback)
    monkeypatch.setattr(socket, 'getaddrinfo', no_dns)
    for scenario, expected in [('positive', 'conformant'), ('negative', 'attention'), ('indeterminate', 'indeterminate')]:
        result = module.run_scenario(scenario)
        assert result['requests_used'] == 1
        cookie = next(f for f in result['findings'] if f['id'] == 'cookie_attributes')
        assert cookie['status'] == expected
        assert 'lab-secret' not in json.dumps(result)
    assert len(addresses) == 3
    import pytest
    with pytest.raises(ValueError):
        module.run_scenario('http://example.com')
    assert len(addresses) == 3


def test_report_recognizes_only_the_exact_positive_cookie_evidence():
    page = (ROOT / 'scripts' / 'fortress_standard_lab_page.html').read_text(encoding='utf-8')
    assert 'cookie_attributes_present' in page
    assert 'Secure, HttpOnly et SameSite' in page
    assert 'Secure, HttpOnly and SameSite' in page


def test_report_has_evidence_recommendation_and_scope_in_both_languages():
    page = (ROOT / 'scripts' / 'fortress_standard_lab_page.html').read_text(encoding='utf-8')
    assert 'f.evidence_code' in page
    assert 'f.severity' in page
    assert 'recommendations' in page
    assert 'sourceLabel' in page
    assert 'TLS' in page


def test_browser_three_scenarios_bilingual_and_print(tmp_path):
    import os
    import socket
    import pytest
    browser = Path.home() / 'AppData/Local/ms-playwright/chromium-1228/chrome-win64/chrome.exe'
    if not browser.is_file():
        pytest.skip('isolated Chromium 1228 unavailable')
    script = tmp_path / 'lab-check.cjs'
    script.write_text(r'''const {chromium}=require(process.argv[2]);
const assert=require('assert'); const fs=require('fs'); const path=require('path');
(async()=>{const origin=process.argv[3].replace(/\/$/,''); const out=process.argv[4];
const context=await chromium.launchPersistentContext(process.argv[6],{headless:true,executablePath:process.argv[5],serviceWorkers:'block',viewport:{width:1280,height:900},args:['--disable-background-networking','--disable-component-update','--disable-sync','--no-first-run','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']});
let blocked=0; await context.route('**/*',r=>{if(new URL(r.request().url()).origin!==origin){blocked++;return r.abort()} return r.continue()});
try{let p=await context.newPage(); await p.goto(origin+'/lab/'); assert.equal(await p.locator('#consent').isChecked(),false); assert.equal(await p.locator('#run').isDisabled(),true); await p.check('#consent');
for(const [s,status,code,state] of [['positive','conformant','cookie_attributes_present','completed'],['negative','attention','cookie_attributes_missing','completed'],['indeterminate','indeterminate','indeterminate','indeterminate']]){
 await p.selectOption('#scenario',s); let response=p.waitForResponse(r=>r.url()===origin+'/lab/audit'&&r.request().method()==='POST'); await p.click('#run'); let received=await response; assert.deepStrictEqual(received.request().postDataJSON(),{scenario:s,route_authorized:true}); let data=await received.json(); assert.equal(data.requests_used,1); let f=data.findings.find(x=>x.id==='cookie_attributes'); assert.equal(f.status,status); assert.equal(f.evidence_code,code); assert.equal(data.route_execution[0].state,state); if(s==='indeterminate'){assert.equal(data.http_status,403); assert(data.findings.length>0); assert(data.findings.every(f=>f.status==='indeterminate')); assert(!data.findings.some(f=>f.status==='conformant'));}
 for(const language of ['fr','en']){await p.selectOption('#lang',language); assert((await p.locator('#consent-label').innerText()).includes('GET') && (await p.locator('#consent-label').innerText()).includes('https://standard-lab.invalid/')); assert((await p.locator('#notice').innerText()).includes(language==='fr'?'CA du laboratoire':'lab CA')); let sec=p.locator('#report section').filter({has:p.locator('h3', {hasText:'cookie_attributes'})}); let content=await sec.innerText(); assert(content.includes(s==='indeterminate'?'unknown':code)); assert(content.includes(s==='positive'?(language==='fr'?'Secure, HttpOnly et SameSite observés':'Secure, HttpOnly and SameSite observed'):s==='negative'?(language==='fr'?'Au moins un attribut':'At least one recommended attribute'):(language==='fr'?'Preuve insuffisante':'Insufficient evidence'))); let report=await p.locator('#report').innerText(); assert(report.includes('503')); assert(report.includes(language==='fr'?(state==='blocked'?'Exécution de la route: bloquée':state==='indeterminate'?'Exécution de la route: indéterminée':'Exécution de la route: terminée'):(state==='blocked'?'Route execution: blocked':state==='indeterminate'?'Route execution: indeterminate':'Route execution: completed'))); if(s==='indeterminate'){assert(report.includes('403')); assert(report.includes(language==='fr'?'Réponse HTTP de refus observée ; aucune conformité déduite.':'HTTP refusal observed; no compliance inferred.'));} let tls=await p.locator('#report section').filter({has:p.locator('h3',{hasText:'https_tls'})}).innerText(); if(state==='completed'){assert(tls.includes('tls_verified'), 'real verified TLS must be visible'); assert(tls.includes(language==='fr'?'nom d’hôte':'hostname'));}else{assert(!tls.includes('tls_verified'));} let metric=await p.locator('#report .metric strong').allTextContents(); let valid=data.findings.filter(f=>f.route_index===1&&f.method==='GET'&&f.route==='[redacted route]'); let att=valid.filter(f=>f.status==='attention'&&f.severity==='low'&&((f.id==='cookie_attributes'&&f.evidence_code==='cookie_attributes_missing')||(['hsts','csp','x_content_type_options','referrer_policy','permissions_policy'].includes(f.id)&&f.evidence_code==='header_absent'))).length; let conf=valid.filter(f=>f.status==='conformant'&&f.severity==='info'&&((f.id==='cookie_attributes'&&f.evidence_code==='cookie_attributes_present')||(state==='completed'&&f.id==='https_tls'&&f.evidence_code==='tls_verified'))).length; assert.deepStrictEqual(metric.map(Number),[att,conf,data.findings.length-att-conf]); let capability=await p.locator('body').getAttribute('data-capability'); assert(!report.includes('lab-secret')&&!report.includes('lab-cookie')&&!report.includes(capability)); await p.emulateMedia({media:'print'}); assert.equal(await sec.innerText(),content); assert.deepStrictEqual(await sec.locator('details').evaluate(el=>[getComputedStyle(el).color,getComputedStyle(el).backgroundColor]),['rgb(0, 0, 0)','rgb(255, 255, 255)']); if(s==='positive'&&out) await p.screenshot({path:path.join(out,'standard-lab-print-'+language+'.png'),fullPage:true}); await p.emulateMedia({media:'screen'}); if(s==='positive'&&out) {await p.screenshot({path:path.join(out,'standard-lab-final-'+language+'.png'),fullPage:true}); await p.evaluate(()=>{let f=result.findings.find(x=>x.id==='https_tls'); f.evidence='RAW_TLS_EVIDENCE_SECRET'; f.reason='RAW_TLS_REASON_SECRET'; render()}); let wait=p.waitForEvent('download'); await p.click('#export'); let download=await wait; let html=fs.readFileSync(await download.path(),'utf8'); let capability=await p.locator('body').getAttribute('data-capability'); assert(!/<script/i.test(html)&&!html.includes('data-capability')&&!html.includes(capability)&&!html.includes('lab-secret')&&!html.includes('lab-cookie')&&!html.includes('http://')&&!html.includes('https://')); assert(!html.includes('RAW_TLS_EVIDENCE_SECRET')&&!html.includes('RAW_TLS_REASON_SECRET')); assert(html.includes('<details open')); assert(html.includes('tls_verified')&&html.includes(language==='fr'?'nom d’hôte':'hostname')&&html.includes(language==='fr'?'fixture uniquement':'fixture only')); fs.writeFileSync(path.join(out,'standard-lab-export-'+language+'.html'),html); } }
}
await p.selectOption('#scenario','positive'); assert.equal(await p.locator('#report section').count(),0); let response=p.waitForResponse(r=>r.url()===origin+'/lab/audit'&&r.request().method()==='POST'); await p.click('#run'); assert.equal((await response).status(),200); await p.selectOption('#lang','fr'); await p.emulateMedia({media:'print'}); if(out) await p.screenshot({path:path.join(out,'standard-lab-final-20261031-done.png'),fullPage:true});
// Isolate each mutation from the genuine server response and restore it afterwards.
await p.emulateMedia({media:'screen'});
for(const language of ['fr','en']){await p.selectOption('#lang',language); const checks=await p.evaluate(()=>{let saved=structuredClone(result), out=[]; let changes=[...['blocked','redirected','indeterminate','not_started','PRIVATE_INVALID'].map(state=>r=>r.route_execution[0].state=state),r=>r.route_execution=[],r=>delete r.route_execution,r=>r.route_execution.push({route_index:1,state:'completed'}),r=>r.route_execution.push({route_index:2,state:'completed'}),r=>r.scope.paths.push('[redacted route]')]; for(let change of changes){result=structuredClone(saved); change(result); render(); out.push({sections:[...document.querySelectorAll('#report section')].map(x=>x.innerText), metrics:[...document.querySelectorAll('#report .metric strong')].map(x=>Number(x.textContent)),report:document.querySelector('#report').innerText});} result=saved;render();return out}); for(const check of checks){assert.equal(check.metrics[0],0);assert.equal(check.metrics[1],0);assert(check.metrics[2]>0);for(const section of check.sections){assert(!/cookie_attributes_present|cookie_attributes_missing|header_absent|tls_verified|PRIVATE_INVALID/.test(section));assert(!section.includes(language==='fr'?'Absence observée':'Absence observed'));assert(!section.includes(language==='fr'?'Secure, HttpOnly et SameSite observés':'Secure, HttpOnly and SameSite observed'));}assert(!check.report.includes('PRIVATE_INVALID'));}}

for(const language of ['fr','en']){await p.selectOption('#lang',language); const checks=await p.evaluate(()=>{let saved=structuredClone(result), out=[]; let changes=[...['blocked','redirected','indeterminate','not_started'].map(state=>r=>r.route_execution[0].state=state),r=>r.route_execution=[],r=>delete r.route_execution,r=>r.route_execution.push({route_index:1,state:'completed'}),r=>r.route_execution.push({route_index:2,state:'completed'})]; for(const change of changes){result=structuredClone(saved); let f=result.findings.find(x=>x.id==='cookie_attributes'); Object.assign(f,{status:'attention',severity:'low',evidence_code:'cookie_attributes_missing'}); change(result);render();out.push({text:document.querySelector('#report').innerText,metrics:[...document.querySelectorAll('#report .metric strong')].map(x=>Number(x.textContent))});}result=saved;render();return out});for(const check of checks){assert.equal(check.metrics[0],0);assert.equal(check.metrics[1],0);assert(!check.text.includes('cookie_attributes_missing'));assert(!check.text.includes(language==='fr'?'Au moins un attribut':'At least one recommended attribute'));}}
if(out){await p.selectOption('#lang','fr');await p.evaluate(()=>{result.route_execution[0].state='blocked';render()});await p.screenshot({path:path.join(out,'standard-lab-refus-20261031-done.png'),fullPage:true});let pending=p.waitForEvent('download');await p.click('#export');let dl=await pending;let html=fs.readFileSync(await dl.path(),'utf8');assert(!/cookie_attributes_present|header_absent|tls_verified|<script|data-capability|lab-secret/i.test(html));fs.writeFileSync(path.join(out,'standard-lab-refus-20261031-done.html'),html,{flag:'wx'});await p.evaluate(()=>{result.route_execution[0].state='completed';render()});}
for(const language of ['fr','en']){await p.selectOption('#lang',language); const results=await p.evaluate(()=>{const saved=structuredClone(result), tlsIndex=saved.findings.findIndex(f=>f.id==='https_tls'), outputs=[]; const mutations=[...['id','status','severity','evidence_code','method','route_index','route'].map(k=>r=>{r.findings.find(f=>f.id==='https_tls')[k]='PRIVATE_INVALID'}), ...['blocked','unknown','indeterminate','redirected','not_started'].map(s=>r=>{r.route_execution[0].state=s}), r=>{r.route_execution=[]}, r=>{delete r.route_execution}, r=>{r.route_execution[0].route_index=2}, r=>{r.route_execution.push({route_index:1,state:'blocked'})}]; for(const mutate of mutations){result=structuredClone(saved); mutate(result); render(); const sections=[...document.querySelectorAll('#report section')]; outputs.push({section:sections[tlsIndex].innerText, conformant:Number(document.querySelectorAll('#report .metric strong')[1].textContent), completed:Array.isArray(result.route_execution)&&result.route_execution.length===1&&result.route_execution[0].route_index===1&&result.route_execution[0].state==='completed'});} result=saved; render(); return outputs}); for(const x of results){assert(!x.section.includes('tls_verified')&&!x.section.includes('PRIVATE_INVALID')); assert(!x.section.includes(language==='fr'?'nom d’hôte validés':'hostname validated')); assert.equal(x.conformant,x.completed?1:0);}}
await p.selectOption('#lang','fr'); await p.emulateMedia({media:'screen'}); await p.locator('#report details').first().evaluate(x=>x.open=false); await p.evaluate(()=>window.dispatchEvent(new Event('beforeprint'))); assert.equal(await p.locator('#report details').first().evaluate(x=>x.open),true); await p.evaluate(()=>window.dispatchEvent(new Event('afterprint'))); assert.equal(await p.locator('#report details').first().evaluate(x=>x.open),false); await p.evaluate(()=>{result.findings[0].evidence='<img src=x onerror=alert(1)>PRIVATE_INJECTION';result.findings[0].reason='PRIVATE_INJECTION';result.findings[0].id='<svg onload=alert(1)>PRIVATE_INJECTION';result.findings[0].route='/PRIVATE_INJECTION';render()}); assert(!(await p.locator('#report').innerHTML()).includes('PRIVATE_INJECTION')); let download=p.waitForEvent('download'); await p.click('#export'); let file=await download; let exported=fs.readFileSync(await file.path(),'utf8'); if(out) fs.writeFileSync(path.join(out,'standard-lab-export-20261031-done.html'),exported,{flag:'wx'}); assert(!/<script/i.test(exported)&&!exported.includes('data-capability')&&!exported.includes('lab-secret')&&!exported.includes('PRIVATE_INJECTION')&&!exported.includes('http://')&&!exported.includes('https://')); assert(exported.includes('<details open')); for(const key of ['status','severity','evidence_code','id','method','route_index']) {let txt=await p.evaluate(k=>{let f=result.findings.find(x=>x.id==='cookie_attributes'); let old=f[k]; f[k]='invalid'; render(); let v=[...document.querySelectorAll('#report section')].find(s=>s.querySelector('h3').textContent===(k==='id'?'unknown':'cookie_attributes')).innerText; f[k]=old; render(); return v},key); assert(!txt.includes('observés sur le cookie synthétique'));}
for(const language of ['fr','en']){await p.selectOption('#lang',language); const checks=await p.evaluate(()=>{result.findings=[{id:'https_tls',status:'attention',severity:'low',evidence_code:'header_absent',method:'GET',route_index:1,route:'/PRIVATE_PATH'},{id:'hsts',status:'attention',severity:'low',evidence_code:'header_absent',method:'GET',route_index:1,route:'[redacted route]'}];render();return [...document.querySelectorAll('#report section')].map(s=>s.innerText)}); assert(!checks[0].includes(language==='fr'?'Absence observée':'Absence observed')); assert(checks[0].includes('unknown')); assert(!checks[0].includes('PRIVATE_PATH')); assert(checks[1].includes(language==='fr'?'Absence observée':'Absence observed'));}
await p.uncheck('#consent'); assert.equal(await p.locator('#run').isDisabled(),true); assert.equal(await p.locator('#report section').count(),0); await p.setViewportSize({width:390,height:844}); assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)); console.log(JSON.stringify({scenarios:3,languages:2,invalid_tuples:6,external_requests_blocked:blocked,print:true}));
}finally{await context.close()}})().catch(e=>{console.error(e);process.exitCode=1});''', encoding='utf-8')
    import signal
    proc = subprocess.Popen([sys.executable, '-I', '-B', str(ROOT / 'scripts/fortress_standard_lab_server.py')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
    try:
        url = urlsplit(proc.stdout.readline().strip())
        assert url.hostname == '127.0.0.1'
        origin = f'http://127.0.0.1:{url.port}'
        completed = subprocess.run(['node', str(script), str(ROOT / 'frontend/node_modules/playwright'), origin,
            os.environ.get('FORTRESS_LAB_SCREENSHOTS', ''), str(browser), str(tmp_path / 'profile')], capture_output=True, text=True, timeout=50)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        print(completed.stdout.strip())
    finally:
        if os.name == 'nt':
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
        proc.wait(timeout=5)
    with pytest.raises(OSError):
        socket.create_connection(('127.0.0.1', url.port), timeout=1)


def test_slow_headers_cannot_extend_absolute_server_lifetime():
    import socket, threading, time
    path = ROOT / 'scripts' / 'fortress_standard_lab_server.py'
    spec = importlib.util.spec_from_file_location('standard_lab_deadline', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stopped = threading.Event()
    with module.LabServer(('127.0.0.1', 0), module.Handler) as server:
        server.capability = 'test-only'
        worker = threading.Thread(target=module.serve_bounded, args=(server, stopped, .5))
        started = time.monotonic()
        worker.start()
        with socket.create_connection(server.server_address, timeout=2) as conn:
            conn.sendall(b'GET /lab/ HTTP/1.1\r\nHost: ')
            worker.join(2)
            assert not worker.is_alive()
            assert time.monotonic() - started < 1.8
            conn.settimeout(1)
            assert conn.recv(1024) == b''


def test_interrupted_slow_headers_never_emit_traceback_or_request(capsys):
    import socket, threading
    path = ROOT / 'scripts' / 'fortress_standard_lab_server.py'
    spec = importlib.util.spec_from_file_location('standard_lab_private_errors', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stopped = threading.Event()
    with module.LabServer(('127.0.0.1', 0), module.Handler) as server:
        server.capability = 'test-only'
        worker = threading.Thread(target=module.serve_bounded, args=(server, stopped, .3))
        worker.start()
        with socket.create_connection(server.server_address, timeout=2) as conn:
            conn.sendall(b'GET /private-marker HTTP/1.1\r\nHost: ')
            worker.join(3)
            assert not worker.is_alive()
    assert capsys.readouterr().err == ''


def test_protocol_error_does_not_reflect_sensitive_method():
    import socket, threading
    path = ROOT / 'scripts' / 'fortress_standard_lab_server.py'
    spec = importlib.util.spec_from_file_location('standard_lab_protocol_privacy', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stopped = threading.Event()
    with module.LabServer(('127.0.0.1', 0), module.Handler) as server:
        server.capability = 'test-only'
        worker = threading.Thread(target=module.serve_bounded, args=(server, stopped, 3))
        worker.start()
        try:
            with socket.create_connection(server.server_address, timeout=2) as conn:
                conn.sendall(b'PRIVATESECRET /lab/ HTTP/1.1\r\nHost: 127.0.0.1:' + str(server.server_port).encode() + b'\r\nConnection: close\r\n\r\n')
                reply = b''
                while True:
                    chunk = conn.recv(4096)
                    if not chunk: break
                    reply += chunk
            assert b'PRIVATESECRET' not in reply
        finally:
            stopped.set()
            worker.join(3)


def test_windows_ctrl_break_closes_slow_client_and_listener():
    import os, signal, socket, time
    import pytest
    if os.name != 'nt':
        pytest.skip('Windows console signal only')
    proc = subprocess.Popen([sys.executable, '-I', '-B', str(ROOT / 'scripts' / 'fortress_standard_lab_server.py')],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    conn = None
    try:
        url = urlsplit(proc.stdout.readline().strip())
        conn = socket.create_connection((url.hostname, url.port), timeout=2)
        conn.sendall(b'GET /lab/ HTTP/1.1\r\nHost: ')
        started = time.monotonic()
        proc.send_signal(signal.CTRL_BREAK_EVENT)
        proc.wait(timeout=5)
        assert time.monotonic() - started < 5
        conn.settimeout(2)
        assert conn.recv(1024) == b''
        with pytest.raises(OSError):
            socket.create_connection((url.hostname, url.port), timeout=1)
        assert proc.stderr.read() == ''
    finally:
        if conn is not None: conn.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_http_server_requires_capability_and_accepts_only_fixed_scenario():
    proc = subprocess.Popen([sys.executable, '-I', '-B', str(ROOT / 'scripts' / 'fortress_standard_lab_server.py')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        url = urlsplit(proc.stdout.readline().strip())
        assert url.hostname == '127.0.0.1' and url.path == '/lab/'
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
        conn.request('GET', '/lab/', headers={'Origin': 'http://attacker.invalid'})
        rejected = conn.getresponse()
        assert rejected.status == 403
        rejected.read()
        conn.close()
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
        conn.request('GET', '/lab/')
        response = conn.getresponse()
        page = response.read().decode()
        assert response.status == 200
        token = re.search(r'data-capability="([A-Za-z0-9_-]+)"', page).group(1)
        assert len(token) >= 40
        for bad_host in ('attacker.invalid', f'localhost:{url.port}', '127.0.0.1'):
            check = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
            check.request('GET', '/lab/', headers={'Host': bad_host})
            denied = check.getresponse()
            assert denied.status == 403 and token.encode() not in denied.read()
            check.close()
        origin = f'http://127.0.0.1:{url.port}'
        body = json.dumps({'scenario': 'negative', 'route_authorized': True})
        headers = {'Origin': origin, 'Content-Type': 'application/json', 'X-Fortress-Capability': token, 'X-Fortress-CSRF': 'same-origin'}
        conn.request('POST', '/lab/audit', body, {**headers, 'X-Fortress-Capability': 'wrong'})
        assert conn.getresponse().status == 403
        conn.close()
        for bad_body, bad_headers, expected in [
            (body, {**headers, 'Origin': 'http://attacker.invalid'}, 403),
            (json.dumps({'scenario': 'negative', 'url': 'http://example.com'}), headers, 400),
            ('{"scenario":"negative","scenario":"positive"}', headers, 400),
            (json.dumps({'scenario': 'http://example.com'}), headers, 400),
        ]:
            conn = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
            conn.request('POST', '/lab/audit', bad_body, bad_headers)
            response = conn.getresponse()
            assert response.status == expected
            response.read()
            conn.close()
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
        conn.request('POST', '/lab/audit', body, headers)
        response = conn.getresponse()
        result = json.loads(response.read())
        assert response.status == 200 and result['requests_used'] == 1
        assert next(f for f in result['findings'] if f['id'] == 'cookie_attributes')['status'] == 'attention'
        conn.close()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
