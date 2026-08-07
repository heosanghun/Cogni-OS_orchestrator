#!/bin/sh
set -eu

# Production consumes only a separately staged, root-owned wheel.  Nothing is
# imported or installed from the caller's current working directory.
OPENSSL=/usr/bin/openssl
SYSTEM_PYTHON=/usr/bin/python3
STAGING_ROOT=/var/lib/cogni-os/snapshot-broker
WHEEL="$STAGING_ROOT/cogni_os-1.0.0-py3-none-any.whl"
RUNTIME_ROOT=/opt/cogni-os/snapshot-broker-v1
PYTHON="$RUNTIME_ROOT/venv/bin/python"
KEY_ROOT=/etc/cogni-os/snapshot-broker
PRIVATE_KEY="$KEY_ROOT/ed25519-private.pem"
PUBLIC_KEY="$KEY_ROOT/ed25519-public.pem"
OPENSSL_DIGEST="$KEY_ROOT/openssl.sha256"
RUNTIME_MANIFEST="$KEY_ROOT/runtime.json"
SERVICE=/etc/systemd/system/cogni-snapshot-broker.service

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  echo "installer must run as root" >&2
  exit 1
fi
for executable in "$OPENSSL" "$SYSTEM_PYTHON" /usr/bin/install /usr/bin/sha256sum /usr/bin/stat; do
  if [ ! -x "$executable" ]; then
    echo "required fixed executable is unavailable: $executable" >&2
    exit 1
  fi
done
if [ -L "$OPENSSL" ]; then
  echo "fixed /usr/bin/openssl may not be a symlink" >&2
  exit 1
fi

if ! /usr/bin/getent group cogni-broker >/dev/null 2>&1; then
  /usr/sbin/groupadd --system cogni-broker
fi
if [ ! -f "$WHEEL" ] || [ -L "$WHEEL" ]; then
  echo "stage one root-owned wheel at $WHEEL" >&2
  exit 1
fi
for component in /var /var/lib /var/lib/cogni-os "$STAGING_ROOT" "$WHEEL"; do
  if [ ! -e "$component" ] || [ -L "$component" ] ||
     [ "$(/usr/bin/stat -c %u "$component")" -ne 0 ] ||
     [ $((0$(/usr/bin/stat -c %a "$component") & 0022)) -ne 0 ]; then
    echo "staged wheel ancestry must be root-owned and not group/world writable: $component" >&2
    exit 1
  fi
done
if [ -e "$RUNTIME_ROOT" ] || [ -e "$PRIVATE_KEY" ] || [ -e "$PUBLIC_KEY" ] ||
   [ -e "$RUNTIME_MANIFEST" ] || [ -e "$SERVICE" ]; then
  echo "refusing to replace an existing broker runtime, key, manifest, or service" >&2
  exit 1
fi

/usr/bin/install -d -o root -g root -m 0755 /opt/cogni-os
/usr/bin/install -d -o root -g root -m 0755 "$RUNTIME_ROOT"
"$SYSTEM_PYTHON" -I -m venv --copies "$RUNTIME_ROOT/venv"
"$PYTHON" -I -m pip --isolated install \
  --no-deps --no-index --only-binary=:all: "$WHEEL"

PACKAGE_ROOT="$("$PYTHON" -I -c 'import pathlib,cogni_os; print(pathlib.Path(cogni_os.__file__).resolve().parent)')"
case "$PACKAGE_ROOT" in
  "$RUNTIME_ROOT"/venv/lib/python*/site-packages/cogni_os) ;;
  *) echo "installed package escaped the fixed runtime" >&2; exit 1 ;;
esac
/usr/bin/chown -R root:root "$RUNTIME_ROOT"
/usr/bin/find "$RUNTIME_ROOT" -type d -exec /usr/bin/chmod 0555 {} +
/usr/bin/find "$RUNTIME_ROOT" -type f -exec /usr/bin/chmod 0444 {} +
/usr/bin/chmod 0555 "$PYTHON"

# The unprivileged transport client must traverse this directory to verify the
# public key, runtime manifest and OpenSSL digest. Only the private key stays
# root-only; the directory itself is immutable but traversable.
/usr/bin/install -d -o root -g root -m 0755 "$KEY_ROOT"
umask 077
"$OPENSSL" genpkey -algorithm ED25519 -out "$PRIVATE_KEY"
"$OPENSSL" pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
/usr/bin/chown root:root "$PRIVATE_KEY" "$PUBLIC_KEY"
/usr/bin/chmod 0600 "$PRIVATE_KEY"
/usr/bin/chmod 0644 "$PUBLIC_KEY"
/usr/bin/sha256sum "$OPENSSL" | /usr/bin/cut -d ' ' -f 1 > "$OPENSSL_DIGEST"
/usr/bin/chown root:root "$OPENSSL_DIGEST"
/usr/bin/chmod 0644 "$OPENSSL_DIGEST"

WHEEL_SHA="$(/usr/bin/sha256sum "$WHEEL" | /usr/bin/cut -d ' ' -f 1)"
PYTHON_SHA="$(/usr/bin/sha256sum "$PYTHON" | /usr/bin/cut -d ' ' -f 1)"
PACKAGE_SHA="$("$PYTHON" -I -c 'import pathlib,sys; from cogni_os.snapshot_broker_protocol import package_tree_sha256; print(package_tree_sha256(pathlib.Path(sys.argv[1])))' "$PACKAGE_ROOT")"
export WHEEL_SHA PYTHON_SHA PACKAGE_SHA PACKAGE_ROOT PYTHON
"$PYTHON" -I -c 'import json,os,sys; d={"entry_module":"cogni_os.snapshot_broker","package_root":os.environ["PACKAGE_ROOT"],"package_tree_sha256":os.environ["PACKAGE_SHA"],"python_path":os.environ["PYTHON"],"python_sha256":os.environ["PYTHON_SHA"],"runtime_id":"cogni-os-snapshot-broker-runtime-v1","schema_version":1,"wheel_sha256":os.environ["WHEEL_SHA"]}; sys.stdout.buffer.write(json.dumps(d,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())' > "$RUNTIME_MANIFEST"
/usr/bin/chown root:root "$RUNTIME_MANIFEST"
/usr/bin/chmod 0644 "$RUNTIME_MANIFEST"

if [ "$(/usr/bin/stat -c '%u:%g:%a' "$KEY_ROOT")" != '0:0:755' ] ||
   [ "$(/usr/bin/stat -c '%u:%g:%a' "$PRIVATE_KEY")" != '0:0:600' ] ||
   [ "$(/usr/bin/stat -c '%u:%g:%a' "$PUBLIC_KEY")" != '0:0:644' ] ||
   [ "$(/usr/bin/stat -c '%u:%g:%a' "$OPENSSL_DIGEST")" != '0:0:644' ] ||
   [ "$(/usr/bin/stat -c '%u:%g:%a' "$RUNTIME_MANIFEST")" != '0:0:644' ]; then
  echo "broker trust material ownership or mode is unsafe" >&2
  exit 1
fi

/usr/bin/tee "$SERVICE" >/dev/null <<'EOF'
[Unit]
Description=Cogni-OS privileged committed-snapshot FD broker
After=local-fs.target
Before=cogni-os.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/cogni-os/snapshot-broker-v1/venv/bin/python -I -m cogni_os.snapshot_broker serve
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectSystem=strict
ProtectHome=read-only
InaccessiblePaths=-/usr/bin/git -/usr/lib/git-core -/usr/libexec/git-core
ReadWritePaths=/run/cogni-os
RuntimeDirectory=cogni-os
RuntimeDirectoryMode=0755
UMask=0007
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
/usr/bin/chown root:root "$SERVICE"
/usr/bin/chmod 0644 "$SERVICE"
/usr/bin/systemctl daemon-reload

echo "Immutable broker runtime installed. Enrol the runner account explicitly:"
echo "  usermod -aG cogni-broker <runner-user>"
echo "Then enable the service and run the root Linux integration gate."
echo "Trusted status remains NO_GO until that independent gate passes."
