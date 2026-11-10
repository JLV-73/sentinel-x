"""Real Windows pipe and job tests; all markers and paths are synthetic."""
import os
import sys
import time
import tempfile
import threading
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch

from app.fortress_job import run_gated


@unittest.skipUnless(os.name == 'nt', 'Windows job required')
class WorkerBoundsTests(unittest.TestCase):
    def test_overflow_is_rejected_before_deadline_and_worker_cannot_write_later(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'fictional-late-marker'
            code = ("import sys,time,pathlib;sys.stdin.buffer.readline();"
                    "sys.stdout.buffer.write(b'X'*32769);sys.stdout.buffer.flush();"
                    "time.sleep(2);pathlib.Path(sys.argv[1]).write_text('fictional')")
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'Invalid result'):
                run_gated([sys.executable, '-c', code, str(marker)], 4)
            self.assertLess(time.monotonic() - start, 1.5)
            time.sleep(2.3)
            self.assertFalse(marker.exists())

    def test_api_keeps_mutex_until_overflow_job_cleanup(self):
        from app import fortress_mvp_api as api
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'fictional-ready'
            late = Path(directory) / 'fictional-late'
            code = ("import sys,time,pathlib;sys.stdin.buffer.read();"
                    "pathlib.Path(sys.argv[1]).write_text('fictional');time.sleep(.6);"
                    "sys.stdout.buffer.write(b'X'*32769);sys.stdout.buffer.flush();"
                    "time.sleep(1);pathlib.Path(sys.argv[2]).write_text('fictional')")
            def real_worker(_args, timeout, payload):
                return run_gated([sys.executable, '-c', code, str(ready), str(late)], timeout, payload)
            errors = []
            def work():
                try:
                    api._run_live('https://example.invalid/', 'https://example.invalid/')
                except Exception as exc:
                    errors.append(type(exc))
            with patch.object(api, 'run_gated', side_effect=real_worker):
                thread = threading.Thread(target=work)
                thread.start()
                deadline = time.monotonic() + 4
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists())
                with self.assertRaises(BlockingIOError):
                    api._run_live('https://example.invalid/', 'https://example.invalid/')
                thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [ValueError])
                self.assertTrue(api._LIVE_LOCK.acquire(blocking=False))
                api._LIVE_LOCK.release()
                time.sleep(1.2)
                self.assertFalse(late.exists())

    def test_overflow_traceback_does_not_retain_output_or_payload(self):
        code = ("import sys,time;sys.stdin.buffer.read();"
                "sys.stdout.buffer.write(b'FAKE_'+b'STDOUT_MARKER'+b'X'*32769);"
                "sys.stdout.buffer.flush();time.sleep(2)")
        try:
            run_gated([sys.executable, '-c', code], 3, b'FAKE_PAYLOAD_MARKER')
        except ValueError as exc:
            frames = traceback.TracebackException.from_exception(exc, capture_locals=True).stack
            found = False
            for frame in frames:
                if frame.filename.replace('\\', '/').endswith('/app/fortress_job.py'):
                    found = True
                    self.assertNotIn('FAKE_STDOUT_MARKER', repr(frame.locals))
                    self.assertNotIn('FAKE_PAYLOAD_MARKER', repr(frame.locals))
            self.assertTrue(found)
        else:
            self.fail('overflow accepted')

    def test_exact_limit_and_noisy_stderr_do_not_deadlock(self):
        code = ("import sys;sys.stdin.buffer.read();"
                "sys.stderr.buffer.write(b'E'*100000);"
                "sys.stdout.buffer.write(b'X'*32768)")
        self.assertEqual(run_gated([sys.executable, '-c', code], 5, b'fictional'), b'X' * 32768)

    def test_expired_deadline_rejects_output_after_delayed_wait(self):
        from subprocess import Popen
        original_wait = Popen.wait
        calls = 0

        def delayed_wait(process, *args, **kwargs):
            nonlocal calls
            calls += 1
            result = original_wait(process, *args, **kwargs)
            if calls == 1:
                time.sleep(.5)
            return result

        code = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'ok')"
        with patch.object(Popen, 'wait', delayed_wait):
            with self.assertRaisesRegex(TimeoutError, 'job deadline'):
                run_gated([sys.executable, '-c', code], .25)

    def test_expired_deadline_rejects_output_after_delayed_cleanup(self):
        from subprocess import Popen
        original_wait = Popen.wait
        calls = 0

        def delayed_wait(process, *args, **kwargs):
            nonlocal calls
            calls += 1
            result = original_wait(process, *args, **kwargs)
            if calls == 2:
                time.sleep(.5)
            return result

        code = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'ok')"
        with patch.object(Popen, 'wait', delayed_wait):
            with self.assertRaisesRegex(TimeoutError, 'job deadline'):
                run_gated([sys.executable, '-c', code], .25)

    def test_native_cleanup_failures_reject_output(self):
        from app import fortress_job
        real_loader = fortress_job.ctypes.WinDLL
        code = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'ok')"

        for name in ('TerminateJobObject', 'QueryInformationJobObject', 'CloseHandle'):
            with self.subTest(native_call=name):
                reached = []
                kernel = real_loader('kernel32', use_last_error=True)
                native = getattr(kernel, name)

                class FailedCall:
                    def __setattr__(self, key, value):
                        setattr(native, key, value)

                    def __call__(self, *args):
                        reached.append(name)
                        native(*args)  # perform real cleanup; inject only the reported failure
                        return 0

                setattr(kernel, name, FailedCall())
                with patch.object(fortress_job.ctypes, 'WinDLL', return_value=kernel):
                    with self.assertRaisesRegex(RuntimeError, 'job cleanup failed'):
                        run_gated([sys.executable, '-c', code], 3)
                self.assertTrue(reached, name + ' was not exercised')

    def test_slow_worker_times_out_without_late_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'fictional-timeout-marker'
            code = ("import sys,time,pathlib;sys.stdin.buffer.readline();"
                    "sys.stdout.buffer.write(b'X');sys.stdout.buffer.flush();"
                    "time.sleep(1);pathlib.Path(sys.argv[1]).write_text('fictional')")
            with self.assertRaises(TimeoutError):
                run_gated([sys.executable, '-c', code, str(marker)], .3)
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    def test_overflow_terminates_descendant_before_return(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'fictional-descendant-marker'
            descendant = ("import time,pathlib,sys;time.sleep(1.2);"
                          "pathlib.Path(sys.argv[1]).write_text('fictional')")
            code = ("import sys,subprocess;sys.stdin.buffer.readline();"
                    "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]],"
                    "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                    "sys.stdout.buffer.write(b'X'*32769);sys.stdout.buffer.flush();"
                    "__import__('time').sleep(3)")
            with self.assertRaisesRegex(ValueError, 'Invalid result'):
                run_gated([sys.executable, '-c', code, str(marker), descendant], 5)
            time.sleep(1.5)
            self.assertFalse(marker.exists())
