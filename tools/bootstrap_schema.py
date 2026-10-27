"""Fetch a pinned external CISA validation resource; never overwrite a file."""
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
import hashlib,json,os,re,tempfile,time

ROOT=Path(__file__).resolve().parents[1]
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('Unexpected source redirect refused')

def install(root=ROOT,opener=None):
    root=Path(root)
    config=json.loads((root/'config/kev-schema.source.json').read_text(encoding='utf-8'))
    url=urlparse(config['url'])
    if (url.scheme!='https' or url.netloc!='raw.githubusercontent.com' or url.query or url.fragment
        or not re.fullmatch(r'/cisagov/kev-data/[a-f0-9]{40}/known_exploited_vulnerabilities_schema.json',url.path)
        or not re.fullmatch(r'[a-f0-9]{64}',config['sha256'])):
        raise ValueError('Unexpected validation-resource origin or hash')
    target=root/'backend/app/kev_schema.json'
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest()!=config['sha256']:
            raise ValueError('Existing schema differs; preserved without overwrite')
        return 'Already verified: '+config['sha256']
    open_source=opener or build_opener(ProxyHandler({}),NoRedirect()).open
    request=Request(config['url'],headers={'Accept':'application/json','Accept-Encoding':'identity','User-Agent':'SENTINEL-X/schema-bootstrap'})
    raw=bytearray()
    deadline=time.monotonic()+20
    with open_source(request,timeout=20) as response:
        if response.status!=200 or response.headers.get('Content-Encoding','identity').lower() not in ('','identity'):
            raise ValueError('Unexpected source HTTP status or encoding')
        read_one=getattr(response,'read1',None)
        while True:
            if time.monotonic()>=deadline:raise TimeoutError('Schema download time budget exceeded')
            # Return control between body reads instead of filling a large buffer.
            chunk=read_one(4096) if callable(read_one) else response.read(1)
            if time.monotonic()>=deadline:raise TimeoutError('Schema download time budget exceeded')
            if not chunk:break
            if len(raw)+len(chunk)>131072:raise ValueError('Schema size limit exceeded')
            raw.extend(chunk)
    if hashlib.sha256(raw).hexdigest()!=config['sha256']:
        raise ValueError('Schema SHA-256 mismatch; nothing installed')
    json.loads(raw)
    target.parent.mkdir(parents=True,exist_ok=True)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent,prefix='.schema-',suffix='.tmp',delete=False) as stream:
            temporary=Path(stream.name);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        # Atomic fail-if-existing publication; no overwrite on concurrent install.
        os.link(temporary,target)
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)
    return 'Installed and verified: '+config['sha256']

if __name__=='__main__':
    print(install())
