#!/usr/bin/env bash
# Offline repository assembly only. No upload/network publication.
set -euo pipefail
: "${NAKPANEL_APT_SIGNING_KEY_ID:?provide preprovisioned GPG release signing identity}"
packages="${1:?candidate directory required}"
output="${2:?new repository output directory required}"
qualification="${3:?reviewed qualification JSON required}"
python3 - "${packages}" "${qualification}" <<'PY'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]);q=json.load(open(sys.argv[2]))
if q.get('qualified') is not True or not q.get('security_update_owner') or not q.get('security_response_policy'):
 raise SystemExit('production package qualification/security owner missing')
for architecture in ('amd64','arm64'):
 for minor in ('83','84'):
  found=list(root.glob('nakpanel-php'+minor+'_*_'+architecture+'.deb'))
  if len(found)!=1:raise SystemExit('requires exactly one qualified version/architecture candidate')
  package=found[0];digest=hashlib.sha256(package.read_bytes()).hexdigest()
  if q.get('artifacts',{}).get(package.name)!=digest:raise SystemExit('package digest not explicitly qualified')
  actual=subprocess.check_output(['dpkg-deb','--field',str(package),'Package'],text=True).strip()
  if actual!='nakpanel-php'+minor:raise SystemExit('foreign package family rejected')
checks=('configuration','fastcgi','cli','composer','wp_cli','workers','tenant_isolation','security_patch_delivery','failed_update_recovery')
if any(q.get('checks',{}).get(architecture,{}).get(check) is not True for architecture in ('amd64','arm64') for check in checks):
 raise SystemExit('incomplete native profile/architecture qualification')
PY
[[ ! -e "${output}" ]] || { echo 'repository output exists' >&2; exit 1; }
mkdir -p "${output}/pool/main" "${output}/dists/resolute/main/binary-amd64" "${output}/dists/resolute/main/binary-arm64"
cp "${packages}"/nakpanel-php{83,84}_*.deb "${output}/pool/main/"
cp "${qualification}" "${output}/qualification.json"
cd "${output}"
for architecture in amd64 arm64; do
 apt-ftparchive --arch "${architecture}" packages pool/main > "dists/resolute/main/binary-${architecture}/Packages"
 gzip -n -k "dists/resolute/main/binary-${architecture}/Packages"
done
apt-ftparchive -o APT::FTPArchive::Release::Origin=Nakpanel -o APT::FTPArchive::Release::Label=Nakpanel \
 -o APT::FTPArchive::Release::Suite=resolute -o APT::FTPArchive::Release::Codename=resolute \
 -o 'APT::FTPArchive::Release::Architectures=amd64 arm64' -o APT::FTPArchive::Release::Components=main \
 -o "APT::FTPArchive::Release::Valid-Until=$(date -u -d '+7 days' '+%a, %d %b %Y %H:%M:%S UTC')" \
 release dists/resolute > dists/resolute/Release
gpg --batch --yes --local-user "${NAKPANEL_APT_SIGNING_KEY_ID}" --clearsign --output dists/resolute/InRelease dists/resolute/Release
gpg --batch --yes --local-user "${NAKPANEL_APT_SIGNING_KEY_ID}" --armor --detach-sign --output dists/resolute/Release.gpg dists/resolute/Release
gpg --verify dists/resolute/InRelease
