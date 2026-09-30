#!/usr/bin/env python3
"""Open a disposable OSMAP UX preview on loopback with public synthetic data.

Run from the checkout: python3 maint/ux/preview.py --minutes 60
The real router, forms and private stores run behind a synthetic mail gateway.
This does not connect to a mail host, validate real credentials, or send email.
Closing the preview deletes its temporary accounts, drafts and preferences.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minutes', type=int, default=30,
                        help='Preview duration, 1 to 1440 minutes (default: 30)')
    args = parser.parse_args()
    if not 1 <= args.minutes <= 1440:
        parser.error('--minutes must be between 1 and 1440')
    repo = Path(__file__).resolve().parents[2]
    if not (repo / 'Cargo.toml').is_file():
        parser.error('Run the checked-in maint/ux/preview.py from an OSMAP checkout')
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    with tempfile.TemporaryDirectory(prefix='osmap-ux-preview-') as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(root),
                   OSMAP_UX_PREVIEW_MINUTES=str(args.minutes))
        with (root / 'fixture.log').open('w+') as log:
            process = subprocess.Popen(
                ['cargo', 'test', '--lib', 'ux_synthetic_browser_server', '--',
                 '--ignored', '--nocapture'], cwd=repo, env=env,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 120
                while not (root / 'ready.json').exists():
                    if process.poll() is not None:
                        raise RuntimeError('Preview build/start failed; run cargo test --lib for diagnostics')
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Preview did not become ready within two minutes')
                    time.sleep(.05)
                ready = json.loads((root / 'ready.json').read_text())
                origin = ready['origin']
                if not ready.get('synthetic') or not origin.startswith('http://127.0.0.1:'):
                    raise RuntimeError('Preview did not provide a synthetic loopback origin')
                print(f'OSMAP synthetic UX preview: {origin}/login', flush=True)
                print('Public fixture account: alice@example.com (or bob@example.com)', flush=True)
                print('Public fixture password: correct horse battery staple | TOTP: 123456', flush=True)
                print(f'Disposable data; no real email. Stops after {args.minutes} minutes or Ctrl+C.', flush=True)
                result = process.wait()
                if result:
                    raise RuntimeError('Preview fixture exited unsuccessfully')
            except KeyboardInterrupt:
                pass
            finally:
                (root / 'stop').touch()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
    print('Preview stopped; disposable data removed.', flush=True)


if __name__ == '__main__':
    main()
