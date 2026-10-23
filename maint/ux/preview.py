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
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time

STOP_SECONDS = 5


def preview_origin(ready):
    origin = ready.get('origin') if type(ready) is dict else None
    match = re.fullmatch(r'http://127\.0\.0\.1:([0-9]{1,5})', origin) if type(origin) is str else None
    if type(ready) is not dict or ready.get('synthetic') is not True or match is None or not 1 <= int(match[1]) <= 65535:
        raise RuntimeError('Preview did not provide a synthetic loopback origin')
    return origin


def stop_preview(process, root):
    """Return any marker error only after proving the born group absent."""
    marker_error = None
    try:
        (root / 'stop').touch()
    except OSError as error:
        marker_error = error
    if process.returncode is None and marker_error is None:
        try:
            process.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:
            pass
    for number in (signal.SIGTERM, signal.SIGKILL):
        if process.returncode is not None:
            break
        try:
            os.killpg(process.pid, number)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:
            if number == signal.SIGKILL:
                raise RuntimeError('Preview process cleanup unconfirmed') from None
    # Reaped PID: observe absence only, never signal a historical group.
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return marker_error
    raise RuntimeError('Preview group remains after direct reap')


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
    root = Path(tempfile.mkdtemp(prefix='osmap-ux-preview-'))
    process = None
    cleanup_confirmed = False
    try:
        os.chmod(root, 0o700)
        env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(root),
                   OSMAP_UX_PREVIEW_MINUTES=str(args.minutes))
        with (root / 'fixture.log').open('w+') as log:
            deadline = time.monotonic() + 120
            previous = signal.pthread_sigmask(signal.SIG_BLOCK,
                {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
            try:
                process = subprocess.Popen(
                    ['cargo', 'test', '--lib', 'ux_synthetic_browser_server', '--',
                     '--ignored', '--nocapture'], cwd=repo, env=env,
                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                    preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous))
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                while not (root / 'ready.json').exists():
                    if process.poll() is not None:
                        raise RuntimeError('Preview build/start failed; run cargo test --lib for diagnostics')
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Preview did not become ready within two minutes')
                    time.sleep(.05)
                ready = json.loads((root / 'ready.json').read_text())
                origin = preview_origin(ready)
                print(f'OSMAP synthetic UX preview: {origin}/login', flush=True)
                print('Public fixture account: alice@example.com (or bob@example.com)', flush=True)
                print('Public fixture password: correct horse battery staple | TOTP: 123456', flush=True)
                print(f'Disposable data; no real email. Stops after {args.minutes} minutes or Ctrl+C.', flush=True)
                result = process.wait(timeout=args.minutes * 60 + 5)
                if result:
                    raise RuntimeError('Preview fixture exited unsuccessfully')
            except KeyboardInterrupt:
                pass
            finally:
                try:
                    if process is not None:
                        marker_error = stop_preview(process, root)
                        cleanup_confirmed = True
                        if marker_error is not None:
                            raise marker_error
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    finally:
        if process is None or cleanup_confirmed:
            shutil.rmtree(root)
        else:
            print(f'Preview cleanup unconfirmed; retained disposable state: {root}', file=sys.stderr)
    print('Preview stopped; disposable data removed.', flush=True)


if __name__ == '__main__':
    main()
