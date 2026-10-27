from pathlib import Path
from tempfile import TemporaryDirectory
from io import BytesIO
from unittest.mock import patch
import hashlib,json,unittest
from bootstrap_schema import install

class Reply(BytesIO):
    status=200
    headers={}

class BootstrapTests(unittest.TestCase):
    def setUp(self):
        (Path(__file__).resolve().parents[1]/'.cache').mkdir(exist_ok=True)
    def prepare(self,root,raw):
        (root/'config').mkdir()
        (root/'config/kev-schema.source.json').write_text(json.dumps({'url':'https://raw.githubusercontent.com/cisagov/kev-data/'+'a'*40+'/known_exploited_vulnerabilities_schema.json','sha256':hashlib.sha256(raw).hexdigest()}),encoding='utf-8')
    def test_installs_verified_bytes_and_reuses_without_network(self):
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'.cache') as folder:
            root=Path(folder);raw=b'{"type":"object"}';self.prepare(root,raw)
            self.assertIn('Installed',install(root,lambda *a,**k:Reply(raw)))
            self.assertEqual((root/'backend/app/kev_schema.json').read_bytes(),raw)
            self.assertIn('Already verified',install(root,lambda *a,**k:(_ for _ in ()).throw(AssertionError('Network forbidden'))))
    def test_bad_download_never_installs(self):
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'.cache') as folder:
            root=Path(folder);self.prepare(root,b'{}')
            with self.assertRaisesRegex(ValueError,'SHA-256'):install(root,lambda *a,**k:Reply(b'corrupt'))
            self.assertFalse((root/'backend/app/kev_schema.json').exists())
    def test_slow_progress_exhausts_total_budget_without_installing(self):
        for supports_read1 in (True,False):
            with self.subTest(read1=supports_read1),TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'.cache') as folder:
                root=Path(folder);raw=b'{"type":"object"}';self.prepare(root,raw)
                elapsed=[0.0]
                class SlowReply(Reply):
                    def read1(self,size=-1):
                        elapsed[0]+=6
                        return super().read(1)
                    def read(self,size=-1):
                        # Model read(n) filling its buffer while bytes keep arriving.
                        received=bytearray()
                        while size<0 or len(received)<size:
                            elapsed[0]+=6
                            chunk=super().read(1)
                            if not chunk:break
                            received.extend(chunk)
                        return bytes(received)
                response=SlowReply(raw)
                if not supports_read1:response.read1=None
                with patch('time.monotonic',lambda:elapsed[0]),self.assertRaisesRegex(TimeoutError,'budget'):
                    install(root,lambda *a,**k:response)
                self.assertGreaterEqual(elapsed[0],20)
                self.assertLessEqual(elapsed[0],26)
                self.assertTrue(response.closed)
                self.assertFalse((root/'backend/app/kev_schema.json').exists())
                self.assertFalse((root/'backend').exists())
                self.assertEqual(list(root.rglob('.schema-*.tmp')),[])
    def test_existing_different_schema_is_preserved(self):
        with TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/'.cache') as folder:
            root=Path(folder);self.prepare(root,b'{}');target=root/'backend/app/kev_schema.json';target.parent.mkdir(parents=True);target.write_bytes(b'keep')
            with self.assertRaisesRegex(ValueError,'preserved'):install(root,lambda *a,**k:Reply(b'{}'))
            self.assertEqual(target.read_bytes(),b'keep')

if __name__=='__main__':unittest.main()
