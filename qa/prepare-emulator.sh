#!/usr/bin/env bash
set -euo pipefail
mkdir -p evidence
: "${ANDROID_HOME:?Android SDK is required}"
SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
AVDMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
IMAGE='system-images;android-36;google_apis_ps16k;x86_64'
test -c /dev/kvm
sudo chmod a+rw /dev/kvm
test -r /dev/kvm && test -w /dev/kvm
free -b > evidence/host-before.txt
df -B1 . >> evidence/host-before.txt
# Live availability is checked again by the actual SDK manager on this runner.
"$SDKMANAGER" --list > evidence/sdk-packages.txt
grep -F "$IMAGE" evidence/sdk-packages.txt
# Accept only SDK licenses in the already authorized isolated Android QA environment.
# sdkmanager may close the yes pipe with SIGPIPE; require the sdkmanager exit code.
set +e
yes | "$SDKMANAGER" --licenses > evidence/sdk-licenses.txt 2>&1
license_status=${PIPESTATUS[1]}
set -e
test "$license_status" -eq 0
"$SDKMANAGER" 'platform-tools' 'emulator' 'build-tools;36.1.0' "$IMAGE"
# Standard Ubuntu runners may have the SDK tools without the emulator package.
# Install it before invoking either -accel-check or -version.
"$ANDROID_HOME/emulator/emulator" -accel-check | tee evidence/kvm.txt
grep -qi 'KVM.*usable' evidence/kvm.txt
cp "$ANDROID_HOME/system-images/android-36/google_apis_ps16k/x86_64/package.xml" evidence/image-package.xml
printf 'no\n' | "$AVDMANAGER" create avd --name AuraPDF14_CI_16K --package "$IMAGE" --device pixel_4
cp "$HOME/.android/avd/AuraPDF14_CI_16K.avd/config.ini" evidence/avd-config-before.ini
python3 - <<'EOF'
from pathlib import Path
path = Path.home() / '.android/avd/AuraPDF14_CI_16K.avd/config.ini'
updates = {'hw.ramSize': '3072', 'hw.cpu.ncore': '2', 'hw.lcd.width': '1080',
           'hw.lcd.height': '2280', 'hw.lcd.density': '440', 'disk.dataPartition.size': '4G'}
lines = [line for line in path.read_text().splitlines() if line.split('=', 1)[0].strip() not in updates]
path.write_text('\n'.join(lines + [f'{key}={value}' for key, value in updates.items()]) + '\n')
EOF
cp "$HOME/.android/avd/AuraPDF14_CI_16K.avd/config.ini" evidence/avd-config.ini
"$ANDROID_HOME/emulator/emulator" -version > evidence/emulator-version.txt 2>&1
"$ANDROID_HOME/build-tools/36.1.0/apksigner" verify --print-certs inputs/app/build14.apk > evidence/app-signature.txt
"$ANDROID_HOME/build-tools/36.1.0/apksigner" verify --print-certs inputs/tests/build14-androidTest.apk > evidence/test-signature.txt
grep -F '24b196b94e3474070eec1e3927f671fec24c1fdd01ed48008d7130f463de355f' evidence/app-signature.txt
grep -F '24b196b94e3474070eec1e3927f671fec24c1fdd01ed48008d7130f463de355f' evidence/test-signature.txt
"$ANDROID_HOME/build-tools/36.1.0/aapt2" dump badging inputs/app/build14.apk > evidence/apk-badging.txt
grep -F "package: name='com.aistudio.aurapdf.xqmp' versionCode='14' versionName='1.0.1'" evidence/apk-badging.txt
