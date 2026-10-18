#!/usr/bin/env bash
# Sign candidate package checksums/evidence, never publish or mark qualified.
set -euo pipefail
: "${NAKPANEL_RELEASE_SIGNING_KEY:?provide RSA release signing key}"
root="${1:?package output directory required}"
python3 - "${root}" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);files={}
for path in sorted(root.rglob('*')):
 if path.is_symlink():raise SystemExit('candidate tree contains symlink')
 if path.is_file() and path.name not in ('candidates.json','candidates.sig'):
  files[path.relative_to(root).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
if not any(p.endswith('.deb') for p in files):raise SystemExit('no packages to sign')
(root/'candidates.json').write_text(json.dumps({'schema_version':1,'qualification':'candidate-only','distribution':'resolute','files':files},indent=2,sort_keys=True)+'\n')
PY
openssl dgst -sha256 -sign "${NAKPANEL_RELEASE_SIGNING_KEY}" -out "${root}/candidates.sig" "${root}/candidates.json"
# The inventory/signature contain public release evidence. Keep them readable by
# the non-root CI artifact uploader even when the signer runs under umask 077.
chmod 0644 "${root}/candidates.json" "${root}/candidates.sig"
