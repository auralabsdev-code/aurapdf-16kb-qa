"""Qualify existing build14 bytes on one isolated Linux/KVM emulator; never build an APK."""
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import time
import traceback
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence'
PKG = 'com.aistudio.aurapdf.xqmp'
SERIAL = 'emulator-5580'
APP_SHA = '53a5cb13fbf17da626e07a4171e988a789d8bab16d56dffc01bd327aa8cb1d32'
TEST_SHA = '7f7adf500784c5cf656ace6a5e77a0d986e264493af4a4ec162eb6814adaa8c2'
REQUIRED = ['inputs', 'host', 'identity', 'installed_app', 'cold1', 'saf_documents',
            'navigation', 'readers', 'persistence_configure', 'cold2',
            'persistence_verify', 'fixtures_unchanged', 'collection', 'health']


def write_json(name, value):
    OUT.mkdir(exist_ok=True)
    target = OUT / name
    temp = target.with_suffix(target.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temp.replace(target)


def verify_inputs():
    manifest = json.loads((ROOT / 'inputs/manifest.json').read_text())
    assert manifest['files']['inputs/app/build14.apk'] == APP_SHA
    assert manifest['files']['inputs/tests/build14-androidTest.apk'] == TEST_SHA
    observed = {}
    for name, expected in manifest['files'].items():
        path = (ROOT / name).resolve()
        assert path.is_relative_to(ROOT / 'inputs')
        observed[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert observed[name] == expected, f'Input changed: {name}'
    write_json('input-hashes.json', observed)
    return observed


def validate_instrumentation(text, expected):
    assert re.search(rf'^OK \({expected} tests?\)\s*$', text, re.M), 'Wrong test count or no JUnit success'
    assert re.search(r'^INSTRUMENTATION_CODE: -1\s*$', text, re.M), 'Runner did not finish normally'
    assert not re.search(r'FAILURES|INSTRUMENTATION_FAILED|Process crashed|shortMsg=|AssumptionFailure|SKIPPED', text, re.I)
    blocks = re.findall(r'(.*?INSTRUMENTATION_STATUS_CODE: (-?\d+))', text, re.S)
    passed = []
    for block, code in blocks:
        assert int(code) in (0, 1), f'Failed, skipped or ignored test: {code}'
        if code == '0' and 'INSTRUMENTATION_STATUS: test=' in block:
            passed.append(re.search(r'INSTRUMENTATION_STATUS: test=(.+)', block)[1].strip())
    assert len(passed) == expected, f'Expected {expected} actual completed tests: {passed}'
    return passed


def health_findings(logcat, exit_text):
    patterns = [r'\bANR in\b', r'\bam_anr\b', r"System UI (?:isn.t responding|is not responding)",
                r'\bFATAL EXCEPTION\b', r'\bFatal signal\b', r'\bUnsatisfiedLinkError\b',
                r'\bdlopen failed\b', r'\bCANNOT LINK\b', r'\blmkd\b.*\bKill(?:ing)?\b',
                r'\blowmemorykiller\b.*\bKill(?:ing)?\b',
                r'Killing.*com\.aistudio\.aurapdf.*(?:low mem|cached|empty)']
    found = [line for line in logcat.splitlines() if any(re.search(p, line, re.I) for p in patterns)]
    for line in exit_text.splitlines():
        # Android also associates unrelated WebView isolated processes with the target UID.
        # Keep all records, but only classify app/test processes here.
        m = re.search(r'process=(\S+).*?reason=(\d+)', line)
        if m and m[1].startswith(PKG) and int(m[2]) not in (1, 10):
            found.append(line)
    return found


class Qualification:
    def __init__(self):
        self.sdk = Path(os.environ['ANDROID_HOME'])
        self.adb_exe = self.sdk / 'platform-tools/adb'
        self.result = {'status': 'RUNNING', 'app_sha256': APP_SHA, 'test_sha256': TEST_SHA,
                       'serial': SERIAL, 'required': REQUIRED, 'checks': {},
                       'run_id': os.environ.get('GITHUB_RUN_ID'), 'retries': 0,
                       'commit': os.environ.get('GITHUB_SHA'), 'started_utc': dt.datetime.now(dt.timezone.utc).isoformat()}
        self.emulator = None
        self.logcat = None
        self.stop_samples = threading.Event()
        self.samples = []
        self.background_files = []
        self.cold_pids = []
        self.save()

    def save(self):
        write_json('result.json', self.result)

    def check(self, name, action):
        assert name in REQUIRED
        self.result['checks'][name] = {'status': 'RUNNING'}
        self.save()
        try:
            data = action()
            self.result['checks'][name] = {'status': 'PASS', 'observed': data}
            return data
        except BaseException as error:
            self.result['checks'][name] = {'status': 'FAIL', 'error': str(error)}
            raise
        finally:
            self.save()

    def command(self, args, timeout=45, check=True):
        started = dt.datetime.now(dt.timezone.utc).isoformat()
        record = {'utc': started, 'argv': list(map(str, args))}
        try:
            r = subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout)
            record.update(exit=r.returncode, stderr=r.stderr.decode(errors='replace')[-3000:])
            if check and r.returncode:
                raise RuntimeError(f'Command failed ({r.returncode}): {args}: {record["stderr"]}')
            return r.stdout
        except subprocess.TimeoutExpired as error:
            record['timeout'] = timeout
            (OUT / 'timeout-output.txt').write_bytes((error.stdout or b'') + (error.stderr or b''))
            raise
        finally:
            with (OUT / 'commands.jsonl').open('a', encoding='utf-8') as f:
                f.write(json.dumps(record) + '\n')

    def adb(self, *args, **kwargs):
        return self.command([self.adb_exe, '-s', SERIAL, *args], **kwargs)

    def text(self, *args, **kwargs):
        return self.adb(*args, **kwargs).decode(errors='replace').replace('\r', '').strip()

    def save_adb(self, name, *args, **kwargs):
        data = self.adb(*args, **kwargs)
        (OUT / name).write_bytes(data)
        return data.decode(errors='replace')

    def wait(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            if self.emulator and self.emulator.poll() is not None:
                raise RuntimeError('Emulator exited unexpectedly')
            time.sleep(.5)
        raise TimeoutError(f'Expected state not reached after {timeout}s')

    def tree(self):
        response = self.text('shell', 'uiautomator', 'dump', '/sdcard/aurapdf-ci.xml', timeout=25)
        assert 'dumped to' in response, 'No fresh UI dump; refusing stale XML'
        data = self.adb('exec-out', 'cat', '/sdcard/aurapdf-ci.xml')
        (OUT / 'current-ui.xml').write_bytes(data)
        tree = ET.fromstring(data)
        assert not any("isn't responding" in n.get('text', '') or 'no responde' in n.get('text', '') for n in tree.iter('node')), 'Android ANR dialog'
        return tree

    @staticmethod
    def nodes(tree, label):
        return [n for n in tree.iter('node') if label in (n.get('text'), n.get('content-desc'))
                and n.get('enabled') == 'true' and n.get('bounds') != '[0,0][0,0]']

    def tap_node(self, node):
        bounds = list(map(int, re.findall(r'\d+', node.get('bounds', ''))))
        assert len(bounds) == 4
        self.adb('shell', 'input', 'tap', str((bounds[0] + bounds[2]) // 2), str((bounds[1] + bounds[3]) // 2))

    def tap(self, label):
        def find():
            nodes = self.nodes(self.tree(), label)
            return nodes[0] if len(nodes) == 1 else None
        # ElementTree leaves have false boolean values; return a list to express presence.
        def found():
            node = find()
            return [node] if node is not None else None
        self.tap_node(self.wait(found, 25)[0])

    def capture(self, name):
        self.tree()
        (OUT / f'{name}.xml').write_bytes((OUT / 'current-ui.xml').read_bytes())
        self.save_adb(f'{name}.png', 'exec-out', 'screencap', '-p')

    def library_ready(self):
        tree = self.tree()
        for label in ['Saltar', 'Do not consent', 'No consentir']:
            nodes = self.nodes(tree, label)
            if len(nodes) == 1:
                self.tap_node(nodes[0])
                return False
        return bool(self.nodes(tree, 'Abrir PDF') and self.nodes(tree, 'Biblioteca'))

    def host(self):
        fields = dict(re.findall(r'^(\w+):\s+(\d+) kB', Path('/proc/meminfo').read_text(), re.M))
        available = int(fields['MemAvailable']) * 1024
        # 3GiB guest plus at least 1.5GiB margin. Actual minima are recorded throughout.
        assert available >= 4608 * 1024**2, f'Host memory margin insufficient: {available}'
        assert os.access('/dev/kvm', os.R_OK | os.W_OK), 'KVM unavailable'
        assert os.cpu_count() >= 2
        write_json('host-preflight.json', {'available_bytes': available, 'cpus': os.cpu_count(), 'guest_mib': 3072})
        return {'available_bytes': available, 'cpus': os.cpu_count()}

    def start(self):
        args = [self.sdk / 'emulator/emulator', '-avd', 'AuraPDF14_CI_16K', '-port', '5580',
                '-accel', 'on', '-memory', '3072', '-cores', '2', '-gpu', 'swiftshader',
                '-no-window', '-no-audio', '-no-boot-anim', '-no-snapshot', '-wipe-data']
        write_json('emulator-command.json', list(map(str, args)))
        log = (OUT / 'emulator.log').open('wb')
        self.background_files.append(log)
        self.emulator = subprocess.Popen(list(map(str, args)), stdout=log, stderr=subprocess.STDOUT)
        self.adb('wait-for-device', timeout=180)
        log = (OUT / 'logcat-live.txt').open('wb')
        self.background_files.append(log)
        self.logcat = subprocess.Popen([str(self.adb_exe), '-s', SERIAL, 'logcat', '-b', 'all', '-v', 'threadtime'], stdout=log, stderr=subprocess.STDOUT)
        self.wait(lambda: self.text('shell', 'getprop', 'sys.boot_completed') == '1', 180)
        self.adb('shell', 'input', 'keyevent', '82')
        self.sample_thread = threading.Thread(target=self.sample_loop, daemon=True)
        self.sample_thread.start()

    def identity(self):
        values = {key: self.text('shell', 'getprop', key) for key in ['ro.kernel.qemu', 'ro.build.version.release', 'ro.build.version.sdk', 'ro.product.cpu.abi', 'ro.product.model']}
        values['PAGE_SIZE'] = self.text('shell', 'getconf', 'PAGE_SIZE')
        values['meminfo'] = self.text('shell', 'cat', '/proc/meminfo')
        write_json('identity.json', values)
        assert values['ro.kernel.qemu'] == '1'
        assert values['ro.build.version.sdk'] == '36' and values['ro.build.version.release'] == '16'
        assert values['ro.product.cpu.abi'] == 'x86_64'
        assert values['PAGE_SIZE'] == '16384'
        total = int(re.search(r'MemTotal:\s+(\d+)', values['meminfo'])[1])
        assert 2400 * 1024 <= total <= 3072 * 1024, 'Guest RAM does not match requested 3072 MiB'
        return values

    def installed(self):
        self.adb('install', ROOT / 'inputs/app/build14.apk', timeout=120)
        self.adb('install', ROOT / 'inputs/tests/build14-androidTest.apk', timeout=120)
        package = self.save_adb('installed-package.txt', 'shell', 'dumpsys', 'package', PKG)
        assert 'versionCode=14 ' in package and 'versionName=1.0.1' in package
        assert 'primaryCpuAbi=x86_64' in package
        remote = self.text('shell', 'pm', 'path', PKG).splitlines()
        assert len(remote) == 1 and remote[0].startswith('package:')
        digest = self.text('shell', 'sha256sum', remote[0][8:]).split()[0]
        assert digest == APP_SHA
        runner = self.save_adb('instrumentation.txt', 'shell', 'pm', 'list', 'instrumentation')
        assert PKG + '.test/androidx.test.runner.AndroidJUnitRunner' in runner
        return {'installed_sha256': digest, 'version_code': 14, 'primary_abi': 'x86_64'}

    def cold(self, label):
        self.adb('shell', 'am', 'force-stop', PKG)
        assert not self.text('shell', 'pidof', PKG, check=False)
        result = self.save_adb(label + '-start.txt', 'shell', 'am', 'start', '-W', '-n', PKG + '/com.example.MainActivity', timeout=60)
        assert re.search(r'Status:\s+ok', result)
        assert re.search(r'LaunchState:\s+COLD', result), 'Cold launch not established'
        pid = self.text('shell', 'pidof', PKG)
        assert pid.isdigit() and pid not in self.cold_pids
        self.cold_pids.append(pid)
        self.wait(self.library_ready, 60)
        assert self.text('shell', 'pidof', PKG) == pid, 'Unexpected process replacement during launch'
        self.capture(label + '-ready')
        return {'pid': pid, 'launch_state': 'COLD', 'no_pid_before': True}

    def stage_saf(self):
        base = '/sdcard/Download/AuraPDF_Persistencia_20261107'
        for letter in ['A', 'B']:
            self.adb('shell', 'mkdir', '-p', base + '/' + letter)
            self.adb('push', ROOT / f'inputs/fixtures/{letter}_Igual.pdf', base + '/' + letter + '/Igual.pdf')
        for letter, count in [('A', 3), ('B', 7)]:
            self.wait(self.library_ready, 30)
            self.tap('Abrir PDF')
            self.tap('Show roots')
            # In the drawer Downloads may occur twice; select only the root title.
            def downloads():
                nodes = [n for n in self.nodes(self.tree(), 'Downloads') if n.get('resource-id') == 'android:id/title']
                return nodes if len(nodes) == 1 else None
            self.tap_node(self.wait(downloads)[0])
            self.tap('AuraPDF_Persistencia_20261107')
            self.tap(letter)
            self.tap('Igual.pdf')
            self.wait(lambda: bool(self.nodes(self.tree(), f'1 / {count}')), 40)
            self.capture('saf-' + letter + '-opened')
            self.tap('Volver a biblioteca')
        return {'documents': ['A/Igual.pdf:3', 'B/Igual.pdf:7'], 'source': 'previous synthetic fixtures via actual SAF picker'}

    def navigation(self):
        for label in ['Recientes', 'Favoritos', 'Biblioteca']:
            self.tap(label)
            def selected():
                tree = self.tree()
                parents = {child: parent for parent in tree.iter() for child in parent}
                for node in self.nodes(tree, label):
                    current = node
                    for _ in range(4):
                        if current.get('selected') == 'true':
                            return True
                        current = parents.get(current)
                        if current is None:
                            break
                return False
            self.wait(selected, 20)
            self.capture('navigation-' + label.lower())
        return {'selected_and_displayed': ['Recientes', 'Favoritos', 'Biblioteca']}

    def instrument(self, label, classes, count, phase=None):
        # Raw mode is required: the pretty reporter hides per-test completion codes.
        args = ['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', classes]
        if phase:
            args += ['-e', 'phase', phase]
        args += [PKG + '.test/androidx.test.runner.AndroidJUnitRunner']
        text = self.save_adb('instrument-' + label + '.txt', *args, timeout=300).replace('\r', '')
        passed = validate_instrumentation(text, count)
        if phase:
            assert f'INSTRUMENTATION_STATUS: persistencePhase={phase}' in text
            assert 'INSTRUMENTATION_STATUS: result=PASS' in text
        return {'passed_tests': passed, 'count': count, 'phase': phase}

    def readers(self):
        classes = ('com.example.ReaderRegressionDeviceTest,'
                   'com.example.VerticalReaderDeviceTest#continuousScrollAndPageDialogRenderOnlyAWindow,'
                   'com.example.VerticalReaderDeviceTest#onePageAndMixedOrientationKeepIntrinsicAspectAndOpenAt100')
        result = self.instrument('readers', classes, 4)
        text = (OUT / 'instrument-readers.txt').read_text()
        zoom = float(re.search(r'INSTRUMENTATION_STATUS: pinchZoom=([0-9.]+)', text)[1])
        assert zoom > 1.3
        assert 'INSTRUMENTATION_STATUS: rotationAndRecreation=PASS' in text
        assert 'INSTRUMENTATION_STATUS: sameNamesRealUris=PASS' in text
        return dict(result, pinch_zoom=zoom, rotation_recreation='PASS')

    def fixture_hashes(self):
        result = {}
        manifest = json.loads((ROOT / 'inputs/manifest.json').read_text())
        for letter in ['A', 'B']:
            remote = f'/sdcard/Download/AuraPDF_Persistencia_20261107/{letter}/Igual.pdf'
            digest = self.text('shell', 'sha256sum', remote).split()[0]
            assert digest == manifest['files'][f'inputs/fixtures/{letter}_Igual.pdf']
            result[letter] = digest
        return result

    def sample_loop(self):
        while not self.stop_samples.is_set():
            try:
                row = {'utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                       'host_meminfo': Path('/proc/meminfo').read_text(),
                       'guest_meminfo': self.text('shell', 'cat', '/proc/meminfo', timeout=10),
                       'app_meminfo': self.text('shell', 'dumpsys', 'meminfo', PKG, timeout=12)}
                self.samples.append(row)
                with (OUT / 'memory.jsonl').open('a') as f:
                    f.write(json.dumps(row) + '\n')
            except Exception as error:
                with (OUT / 'sampling-errors.txt').open('a') as f:
                    f.write(str(error) + '\n')
            self.stop_samples.wait(10)

    def collect(self):
        # Each operation is attempted even if an earlier collection command fails.
        errors = []
        jobs = [('logcat-final.txt', ('logcat', '-b', 'all', '-d', '-v', 'threadtime')),
                ('exit-app.txt', ('shell', 'dumpsys', 'activity', 'exit-info', PKG)),
                ('exit-test.txt', ('shell', 'dumpsys', 'activity', 'exit-info', PKG + '.test')),
                ('meminfo-final.txt', ('shell', 'dumpsys', 'meminfo')),
                ('activity-final.txt', ('shell', 'dumpsys', 'activity', 'activities')),
                ('package-final.txt', ('shell', 'dumpsys', 'package', PKG)),
                ('native-files.tar', ('exec-out', 'run-as', PKG, 'tar', '-cf', '-', 'files')),
                ('final-screen.png', ('exec-out', 'screencap', '-p'))]
        for name, args in jobs:
            try:
                self.save_adb(name, *args, timeout=40)
            except Exception as error:
                errors.append({'file': name, 'error': str(error)})
        write_json('collection-errors.json', errors)
        assert not errors, f'Incomplete evidence: {errors}'
        return {'collected': [name for name, _ in jobs]}

    def health(self):
        assert self.logcat and self.logcat.poll() is None, 'Continuous log collector died'
        for f in self.background_files:
            f.flush()
        logcat = (OUT / 'logcat-live.txt').read_text(errors='replace') + (OUT / 'logcat-final.txt').read_text(errors='replace')
        exits = (OUT / 'exit-app.txt').read_text() + (OUT / 'exit-test.txt').read_text()
        findings = health_findings(logcat, exits)
        assert len(self.samples) >= 2, 'Missing continuous memory measurements'
        assert not (OUT / 'sampling-errors.txt').exists(), 'Memory monitoring failed'
        minimum = min(int(re.search(r'MemAvailable:\s+(\d+)', s['host_meminfo'])[1]) for s in self.samples) * 1024
        assert minimum >= 512 * 1024**2, 'Host memory pressure; reservation remains open'
        assert self.emulator.poll() is None, 'Emulator exited'
        write_json('health-findings.json', {'findings': findings, 'memory_samples': len(self.samples), 'minimum_host_available_bytes': minimum})
        assert not findings, 'ANR/crash/native error/low-memory kill observed; reservation remains open'
        return {'findings': 0, 'samples': len(self.samples), 'min_host_available_bytes': minimum}

    def close(self):
        self.stop_samples.set()
        if hasattr(self, 'sample_thread'):
            self.sample_thread.join(timeout=25)
        for process in [self.logcat, self.emulator]:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for f in self.background_files:
            f.close()

    def run(self):
        error = None
        try:
            self.check('inputs', verify_inputs)
            self.check('host', self.host)
            self.start()
            self.check('identity', self.identity)
            self.check('installed_app', self.installed)
            self.check('cold1', lambda: self.cold('cold1'))
            self.check('saf_documents', self.stage_saf)
            self.check('navigation', self.navigation)
            self.check('readers', self.readers)
            self.check('persistence_configure', lambda: self.instrument('configure', 'com.example.LocalPersistenceDeviceTest', 1, 'configure'))
            self.check('cold2', lambda: self.cold('cold2'))
            self.check('persistence_verify', lambda: self.instrument('verify', 'com.example.LocalPersistenceDeviceTest', 1, 'verify'))
            self.check('fixtures_unchanged', self.fixture_hashes)
        except BaseException as exc:
            error = str(exc)
            (OUT / 'failure.txt').write_text(traceback.format_exc(), encoding='utf-8')
        finally:
            if self.emulator is not None:
                try:
                    self.check('collection', self.collect)
                    self.check('health', self.health)
                except BaseException as exc:
                    error = error or str(exc)
            else:
                error = error or 'Emulator not started'
            self.result['status'] = 'PASS' if not error and all(self.result['checks'].get(k, {}).get('status') == 'PASS' for k in REQUIRED) else 'FAIL'
            self.result['error'] = error
            self.result['stability_reservation'] = 'CLOSED_FOR_THIS_X86_64_RUN' if self.result['status'] == 'PASS' else 'OPEN'
            self.result['finished_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
            self.save()
            self.close()
        return 0 if self.result['status'] == 'PASS' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    if args.verify_only:
        verify_inputs()
    else:
        # Actions step timeout sends SIGTERM: save failure and collect before exiting.
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('QA interrupted')))
        raise SystemExit(Qualification().run())
