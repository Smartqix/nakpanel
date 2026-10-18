#!/usr/bin/env python3
"""Assemble matching assets and manifest; only build.sh invokes this writer."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

root, bundle, version, commit, architecture, development = sys.argv[1:]
root, bundle = Path(root), Path(bundle)
# Include the toolchain pin/verifier required by source and bundle installers.
# Every included installation/configuration asset has a signed digest.
shutil.copytree(root / 'deploy', bundle / 'deploy', ignore=shutil.ignore_patterns('multipass', '__pycache__'))
manifest = dict(schema_version=1, version=version, commit=commit,
                go_toolchain='go' + (root/'deploy/release/GO_VERSION').read_text().strip(),
                cgo_enabled=False, os='linux', architecture=architecture,
                cpu_baseline={'amd64':'v1','arm64':'v8.0'}[architecture],
                development=development == 'true', files={})
for path in sorted(bundle.rglob('*')):
    if path.is_symlink():
        raise SystemExit(f'release assets cannot contain symlinks: {path}')
    if path.is_file():
        manifest['files'][path.relative_to(bundle).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
(bundle/'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
