"""A green job requires a complete result, never a skipped or empty test run."""
import json
import os
from pathlib import Path
from runner import REQUIRED, APP_SHA, TEST_SHA

path = Path('evidence/result.json')
if not path.exists():
    raise SystemExit('FAIL: no executed qualification result; stability reservation OPEN')
result = json.loads(path.read_text())
checks = result.get('checks', {})
lines = ['AuraPDF build14 — 16 KB', '', '| Check | Result |', '|---|---|']
lines += [f'| {name} | {checks.get(name, {}).get("status", "NOT EXECUTED")} |' for name in REQUIRED]
summary = '\n'.join(lines) + '\n\nReservation: ' + result.get('stability_reservation', 'OPEN') + '\n'
Path('evidence/SUMMARY.md').write_text(summary)
if os.environ.get('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
        f.write(summary)
assert result['app_sha256'] == APP_SHA and result['test_sha256'] == TEST_SHA
assert result['status'] == 'PASS' and result['retries'] == 0
assert result['required'] == REQUIRED
assert all(checks.get(name, {}).get('status') == 'PASS' for name in REQUIRED), 'Missing, failed or skipped check'
assert checks['readers']['observed']['count'] == 4
assert checks['persistence_configure']['observed']['count'] == 1
assert checks['persistence_verify']['observed']['count'] == 1
assert checks['cold1']['observed']['pid'] != checks['cold2']['observed']['pid']
for name in ['input-hashes.json', 'identity.json', 'host-preflight.json', 'memory.jsonl',
             'logcat-live.txt', 'logcat-final.txt', 'exit-app.txt', 'exit-test.txt',
             'cold1-start.txt', 'cold2-start.txt', 'cold1-ready.png', 'cold2-ready.png',
             'saf-A-opened.png', 'saf-B-opened.png', 'native-files.tar', 'health-findings.json',
             'instrument-readers.txt', 'instrument-configure.txt', 'instrument-verify.txt']:
    evidence = Path('evidence') / name
    assert evidence.is_file() and evidence.stat().st_size > 0, f'Missing evidence: {name}'
print(summary)
