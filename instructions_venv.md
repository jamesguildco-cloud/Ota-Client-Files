Mac: New Venv Device

From any test folder:

mkdir -p ~/venv-test-sb-2
cd ~/venv-test-sb-2
python3 -m venv .venv-device-test
source .venv-device-test/bin/activate
python -m pip install --upgrade pip
pip install requests pyyaml cryptography
cp /Users/username/location/location/ota_client.py 


Create config:

nano ota_client.device-venv-3.yaml
Paste:

server_url: https://serversb.theguildco.com
device_id: device-venv-3
mode: virtual
model: mac-venv-device
channel: stable
base_dir: /Users/username/venv-test-sb-2/.ota_client_device_venv_3 //change path
current_version: 1.0.0
retry_backoff: 5
retry_limit: 5
tenant_id:
client_cert:
client_key:
public_key:
work_dir:
state_path:
event_log:
virtual_slot_dir:

Then -> Allowlist the "device-venv-3" in the dashboard Provisioning tab.


Then run:

python ota_client.py --config ota_client.device-venv-3.yaml --bootstrap-only
python ota_client.py --config ota_client.device-venv-3.yaml --register-only
python ota_client.py --config ota_client.device-venv-3.yaml --once


Expected:

bootstrap command returns quietly
register command returns quietly
once prints either:
OTA applied for version ...
or No update available
Mac: Reuse Same Venv, New Device

You can also use your existing ~/venv-test-sb venv:

cd ~/venv-test-sb
source .venv-device-test/bin/activate
cp ota_client.device-venv-2.yaml ota_client.device-venv-3.yaml

Edit only:

device_id: device-venv-3
base_dir: /Users/username/venv-test-sb/.ota_client_device_venv_3
current_version: 1.0.0
Remove any old generated fields if present:

tenant_id:
client_cert:
client_key:
public_key:
work_dir:
state_path:
event_log:
virtual_slot_dir:

Then run the same three commands.
python ota_client.py --config ota_client.device-venv-3.yaml --bootstrap-only
python ota_client.py --config ota_client.device-venv-3.yaml --register-only
python ota_client.py --config ota_client.device-venv-3.yaml --once




Windows: New Venv Device

Open PowerShell:

mkdir C:\ota-venv-test-1
cd C:\ota-venv-test-1
py -3 -m venv .venv-device-test
.\.venv-device-test\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install requests pyyaml cryptography
If activation is blocked:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv-device-test\Scripts\Activate.ps1
Put ota_client.py in:

C:\ota-venv-test-1\ota_client.py
Create config:

notepad ota_client.device-venv-win-1.yaml
Paste:

server_url: https://serversb.theguildco.com
device_id: device-venv-win-1
mode: virtual
model: windows-venv-device
channel: stable
base_dir: C:\ota-venv-test-1\.ota_client_device_venv_win_1
current_version: 1.0.0
retry_backoff: 5
retry_limit: 5
enant_id:
client_cert:
client_key:
public_key:
work_dir:
state_path:
event_log:
virtual_slot_dir:

Then -> Allowlist the "device-venv-win-1" in the dashboard Provisioning tab.



Run:

python ota_client.py --config ota_client.device-venv-win-1.yaml --bootstrap-only
python ota_client.py --config ota_client.device-venv-win-1.yaml --register-only
python ota_client.py --config ota_client.device-venv-win-1.yaml --once

DB Verification

For any new device:

SELECT set_config('app.tenant_id', 'Test2', false);

SELECT id, tenant_id, provisioning_state, current_version, blacklisted
FROM devices
WHERE id = 'device-venv-3';

SELECT tenant_id, device_id, fingerprint, status
FROM device_certs
WHERE device_id = 'device-venv-3';

SELECT tenant_id, device_id, event_type, created_at
FROM device_events
WHERE device_id = 'device-venv-3'
ORDER BY created_at DESC
LIMIT 20;

SELECT *
FROM download_progress
WHERE device_id = 'device-venv-3'
ORDER BY updated_at DESC;
For Windows, replace device-venv-3 with device-venv-win-1.

Clean Reset

Mac:

rm -rf /Users/username/venv-test-sb/.ota_client_device_venv_3
Windows:

Remove-Item -Recurse -Force C:\ota-venv-test-1\.ota_client_device_venv_win_1
Use a fresh device_id whenever you want a truly clean end-to-end provisioning test.