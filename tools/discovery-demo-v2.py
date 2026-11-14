"""Reproduce a synthetic HTTPS loopback-only A→B→C demo; never overwrites v2."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'backend'))
from app import fortress_discovery_lab as lab

OUT = ROOT / 'reports' / 'sentinel-v024-lab-demo-v2'

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    resume = sys.argv[1:] == ['--resume']
    if resume:
        require(OUT.is_dir() and {p.name for p in OUT.iterdir()} == {'standard.json', 'csp-resource.json'}, 'Unexpected partial output; refusing resume')
    else:
        require(not OUT.exists() and not sys.argv[1:], 'Output already exists or invalid arguments; refusing to overwrite')
    # Explicitly synthetic fixture only. No user-selected destination, DNS or public connection.
    scenarios = {
        'standard': lab._ROUTES.copy(),
        'csp-resource': {
            '/': (200, b'<a href="/jump">next</a><form action="/api/example"></form><script src="/static/demo.js"></script>', None,
                  [('Content-Security-Policy', "script-src 'unsafe-inline'"), ('Content-Security-Policy-Report-Only', "style-src 'unsafe-inline'"), ('Strict-Transport-Security', 'max-age=3600')]),
            '/jump': (302, b'', '/second', []),
            '/second': (200, b'<a href="/third">next</a>', None, []),
            '/third': (200, b'<p>synthetic</p>', None, []),
        },
    }
    original_exchange = lab._one_exchange
    original_connect = socket.socket.connect
    def loopback_only(sock, address):
        require(isinstance(address, tuple) and address[0] == '127.0.0.1', 'Non-loopback connection refused')
        return original_connect(sock, address)
    results, paths = {}, {}
    for name, routes in scenarios.items():
        visited = []
        def capture(path):
            visited.append(path)
            return original_exchange(path)
        if resume:
            result = json.loads((OUT / f'{name}.json').read_text(encoding='utf-8'))
            visited = ['/', '/jump', '/second', '/third']
            require([p['graph_route'] for p in result['intelligence']['pages']] == [lab._id(p) for p in visited], 'unexpected saved paths')
        else:
            with patch.object(lab, '_ROUTES', routes), patch.object(lab, '_one_exchange', side_effect=capture), patch.object(socket.socket, 'connect', loopback_only), patch.object(socket, 'getaddrinfo', side_effect=RuntimeError('DNS forbidden')):
                result = lab.run_lab()
        require(visited == ['/', '/jump', '/second', '/third'], f'{name}: unexpected route order')
        require(result['requests'] == 4 and result['pages'] == 3 and result['complete'] and result['reason'] == 'none', f'{name}: unexpected traversal')
        pages = result['intelligence']['pages']
        require([p['status'] for p in pages] == [200,302,200,200], 'wrong statuses')
        require([p['state'] for p in pages] == ['complete','redirected','complete','complete'], 'wrong states')
        redirect = [r for r in result['graph']['relations'] if r['kind'] == 'redirect']
        require(len(redirect) == 1 and redirect[0]['from'] == lab._id('/jump') and redirect[0]['to'] == lab._id('/second'), 'incorrect redirect attribution')
        raw = json.dumps(result, ensure_ascii=False)
        require('SECRET_EXAMPLE' not in raw and 'standard-lab.invalid' not in raw, 'raw data leaked')
        if name == 'csp-resource':
            require({'form','api','script'} <= {r['kind'] for r in result['graph']['resources']}, 'missing resources')
            require(pages[0]['observations']['csp'] == 'present' and pages[0]['observations']['csp_report_only'] == 'present', 'missing CSP')
        results[name] = result
        paths[name] = visited
    if not resume:
        OUT.mkdir(parents=True, exist_ok=False)
        for name, result in results.items():
            with (OUT / f'{name}.json').open('x', encoding='utf-8', newline='\n') as f:
                json.dump(result, f, ensure_ascii=False, indent=2); f.write('\n')
    subprocess.run(['node', '--no-warnings', '--experimental-strip-types', '--loader', (ROOT/'tools/discovery-demo-v2-loader.mjs').as_uri(), str(ROOT/'tools/discovery-demo-v2-render.mjs'), str(OUT)], cwd=ROOT, check=True)
    sources = ['backend/app/fortress_discovery_lab.py','backend/app/fortress_discovery_intelligence.py','backend/app/fortress_mvp.py','frontend/src/discoveryLabAdapter.ts','frontend/src/discoveryReport.ts','tools/discovery-demo-v2.py','tools/discovery-demo-v2-loader.mjs','tools/discovery-demo-v2-render.mjs']
    files = sorted(p for p in OUT.iterdir() if p.is_file())
    manifest = {'kind':'synthetic owned HTTPS loopback laboratory; not production and not a public audit', 'head': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(), 'source_sha256': {s:sha(ROOT/s) for s in sources}, 'artifacts_sha256':{p.name:sha(p) for p in files}, 'observed_paths':paths, 'notes':['Fixture routes and CSP are synthetic. JSON is structured output, not raw HTTP.', 'No DNS; socket.connect constrained to 127.0.0.1 in this process. No system-wide network isolation claimed.', 'Traversal complete does not mean report complete: redirected page is not analyzed.', 'HTML rendered by the current adapter and renderer; aliases do not disclose real routes.', 'No browser, production API, public TLS, vulnerability or compliance qualification.'], 'reproduce':'PYTHONDONTWRITEBYTECODE=1 python tools/discovery-demo-v2.py (requires absent v2 output directory; preserve prior results)'}
    manifest['run_note'] = 'Fixture executed before loader-path correction; rendering resumed from unchanged saved structured JSON. The final script hash includes this correction and resume support.' if resume else 'Fixture and rendering executed in one run.'
    with (OUT/'manifest.json').open('x',encoding='utf-8',newline='\n') as f:
        json.dump(manifest,f,ensure_ascii=False,indent=2); f.write('\n')
    print('Created', OUT)

if __name__ == '__main__':
    main()
