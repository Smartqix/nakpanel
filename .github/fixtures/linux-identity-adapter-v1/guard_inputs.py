"""Static source guard for a future admitted fixture commit; no root or adapter use."""
import hashlib,json,subprocess
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE='1627bba3c681a884255eb91452dbba74a43ebbdc'
ALLOW=['.github/workflows/linux-identity-adapter.yml', '.github/fixtures/linux-identity-adapter-v1/collector.py', '.github/fixtures/linux-identity-adapter-v1/custody.py', '.github/fixtures/linux-identity-adapter-v1/fixture.go', '.github/fixtures/linux-identity-adapter-v1/fixture_driver.py', '.github/fixtures/linux-identity-adapter-v1/guard_inputs.py', '.github/fixtures/linux-identity-adapter-v1/inputs.json', '.github/fixtures/linux-identity-adapter-v1/projector/go.mod', '.github/fixtures/linux-identity-adapter-v1/projector/go.sum', '.github/fixtures/linux-identity-adapter-v1/projector/main.go', '.github/fixtures/linux-identity-adapter-v1/units/nakpanel.service', '.github/fixtures/linux-identity-adapter-v1/units/nakpanel-agent.service']
INPUTS_SHA='2590fdcf0a622c665da8b67209e692f18e70b6746c81cb411540dcf35968cea5'

def need(value):
    if not value:raise ValueError('fixture source refused')

def main():
    r=subprocess.run(['git','diff','--name-only',SOURCE,'HEAD'],capture_output=True,check=True,timeout=5)
    need(sorted(r.stdout.decode().splitlines())==sorted(ALLOW))
    raw=(HERE/'inputs.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==INPUTS_SHA)
    inputs=json.loads(raw)
    for name,h in inputs['files'].items():need(hashlib.sha256((HERE/name).read_bytes()).hexdigest()==h)
    for role in ('nakpanel','nakpanel-agent'):
        r=subprocess.run(['git','show',SOURCE+':deploy/systemd/'+role+'.service'],capture_output=True,check=True,timeout=5)
        need(r.stdout==(HERE/'units'/str(role+'.service')).read_bytes())

if __name__=='__main__':main()
