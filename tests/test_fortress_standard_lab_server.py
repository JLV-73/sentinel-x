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
    assert findings['hsts'] == 'indeterminate'
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
try{let p=await context.newPage(); await p.goto(origin+'/lab/');
for(const [s,status,code,state] of [['positive','conformant','cookie_attributes_present','completed'],['negative','attention','cookie_attributes_missing','completed'],['indeterminate','indeterminate','indeterminate','blocked']]){
 await p.selectOption('#scenario',s); let response=p.waitForResponse(r=>r.url()===origin+'/lab/audit'&&r.request().method()==='POST'); await p.click('#run'); let data=await (await response).json(); assert.equal(data.requests_used,1); let f=data.findings.find(x=>x.id==='cookie_attributes'); assert.equal(f.status,status); assert.equal(f.evidence_code,code); assert.equal(data.route_execution[0].state,state);
 for(const language of ['fr','en']){await p.selectOption('#lang',language); let sec=p.locator('#report section').filter({has:p.locator('h3', {hasText:'cookie_attributes'})}); let content=await sec.innerText(); assert(content.includes(s==='indeterminate'?'unknown':code)); assert(content.includes(s==='positive'?(language==='fr'?'Secure, HttpOnly et SameSite observés':'Secure, HttpOnly and SameSite observed'):s==='negative'?(language==='fr'?'Au moins un attribut':'At least one recommended attribute'):(language==='fr'?'Preuve insuffisante':'Insufficient evidence'))); let report=await p.locator('#report').innerText(); assert(report.includes('503')); assert(report.includes(language==='fr'?(state==='blocked'?'Exécution de la route: bloquée':'Exécution de la route: terminée'):(state==='blocked'?'Route execution: blocked':'Route execution: completed'))); let capability=await p.locator('body').getAttribute('data-capability'); assert(!report.includes('lab-secret')&&!report.includes('lab-cookie')&&!report.includes(capability)); await p.emulateMedia({media:'print'}); assert.equal(await sec.innerText(),content); await p.emulateMedia({media:'screen'}); if(s==='positive'&&out) await p.screenshot({path:path.join(out,'standard-lab-final-'+language+'.png'),fullPage:true}); }
}
await p.selectOption('#scenario','positive'); let response=p.waitForResponse(r=>r.url()===origin+'/lab/audit'&&r.request().method()==='POST'); await p.click('#run'); assert.equal((await response).status(),200); await p.selectOption('#lang','fr'); await p.emulateMedia({media:'print'}); if(out) await p.screenshot({path:path.join(out,'standard-lab-final-report.png'),fullPage:true});
await p.emulateMedia({media:'screen'}); for(const key of ['status','severity','evidence_code','id']) {let txt=await p.evaluate(k=>{let f=result.findings.find(x=>x.id==='cookie_attributes'); let old=f[k]; f[k]='invalid'; render(); let v=[...document.querySelectorAll('#report section')].find(s=>s.querySelector('h3').textContent===(k==='id'?'invalid':'cookie_attributes')).innerText; f[k]=old; render(); return v},key); assert(!txt.includes('observés sur le cookie synthétique'));}
for(const language of ['fr','en']){await p.selectOption('#lang',language); const checks=await p.evaluate(()=>{result.findings=[{id:'https_tls',status:'attention',severity:'low',evidence_code:'header_absent',method:'GET',route:'/PRIVATE_PATH'},{id:'hsts',status:'attention',severity:'low',evidence_code:'header_absent',method:'GET',route:'[redacted route]'}];render();return [...document.querySelectorAll('#report section')].map(s=>s.innerText)}); assert(!checks[0].includes(language==='fr'?'Absence observée':'Absence observed')); assert(checks[0].includes('unknown')); assert(!checks[0].includes('PRIVATE_PATH')); assert(checks[1].includes(language==='fr'?'Absence observée':'Absence observed'));}
console.log(JSON.stringify({scenarios:3,languages:2,invalid_tuples:4,external_requests_blocked:blocked,print:true}));
}finally{await context.close()}})().catch(e=>{console.error(e);process.exitCode=1});''', encoding='utf-8')
    proc = subprocess.Popen([sys.executable, '-I', '-B', str(ROOT / 'scripts/fortress_standard_lab_server.py')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        url = urlsplit(proc.stdout.readline().strip())
        assert url.hostname == '127.0.0.1'
        origin = f'http://127.0.0.1:{url.port}'
        completed = subprocess.run(['node', str(script), str(ROOT / 'frontend/node_modules/playwright'), origin,
            os.environ.get('FORTRESS_LAB_SCREENSHOTS', ''), str(browser), str(tmp_path / 'profile')], capture_output=True, text=True, timeout=50)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        print(completed.stdout.strip())
    finally:
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
        body = json.dumps({'scenario': 'negative'})
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
