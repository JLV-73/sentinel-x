"""Foreground-only development launcher. Ctrl+C stops both owned children."""
from pathlib import Path
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def build_commands(root, node):
    python = root / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    return {
        'backend': [str(python), '-I', '-m', 'uvicorn', 'app.main:app', '--app-dir', str(root / 'backend'), '--host', '127.0.0.1', '--port', '8007'],
        'frontend': [node, str(root / 'frontend/node_modules/vite/bin/vite.js'), '--host', '127.0.0.1', '--port', '5177', '--strictPort'],
    }


def main():
    node = shutil.which('node')
    if not node:
        raise SystemExit('Node.js introuvable dans le PATH. Aucun outil global ne sera installe.')
    commands = build_commands(ROOT, node)
    if not Path(commands['backend'][0]).is_file() or not Path(commands['frontend'][1]).is_file():
        raise SystemExit('Dependances absentes. Suivre README.md, section reconstruction.')
    # Check only our two application endpoints, not the network or other machines.
    for port in (8007, 5177):
        with socket.socket() as sock:
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                raise SystemExit(f'Port local {port} occupe. Aucun processus existant ne sera arrete.')
    children = []
    stopping = False

    def request_stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, request_stop)
    env = os.environ.copy()
    # Process-local only: never let a caller inject another Python environment.
    for key in ('PYTHONPATH', 'PYTHONHOME'):
        env.pop(key, None)
    cache = ROOT / '.cache' / 'runtime'
    cache.mkdir(parents=True, exist_ok=True)
    env.update({'TEMP': str(cache), 'TMP': str(cache), 'PYTHONUNBUFFERED': '1', 'PYTHONDONTWRITEBYTECODE': '1'})
    try:
        for name, command in commands.items():
            cwd = ROOT / 'frontend' if name == 'frontend' else ROOT
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            children.append(subprocess.Popen(command, cwd=cwd, env=env, creationflags=flags))
        print('\nSENTINEL X / NIGHTFALL — ALPHA 007', flush=True)
        print('Cockpit : http://127.0.0.1:5177 | API : http://127.0.0.1:8007/api/health', flush=True)
        print('Ctrl+C dans CETTE fenetre arrete proprement les deux serveurs. Aucun service permanent.', flush=True)
        while not stopping:
            if any(child.poll() is not None for child in children):
                raise RuntimeError('Un serveur est termine. Verification des messages ci-dessus necessaire.')
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        # Never act on saved PIDs: only processes created by this invocation.
        for child in reversed(children):
            if child.poll() is None:
                try:
                    child.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGINT)
                except OSError:
                    pass
        deadline = time.monotonic() + 12
        for child in reversed(children):
            try:
                child.wait(timeout=max(0.1, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                child.terminate()
                child.wait(timeout=5)
        print('SENTINEL X arrete.', flush=True)


if __name__ == '__main__':
    main()
