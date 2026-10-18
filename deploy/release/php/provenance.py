#!/usr/bin/env python3
"""Capture source/native library inventory plus file-level SPDX and provenance."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import uuid

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--prefix',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
parser.add_argument('--architecture',required=True);parser.add_argument('--version',required=True)
args=parser.parse_args()
lock=json.loads((args.evidence/'sources.lock.json').read_text())
sources=[entry for entry in lock['php'].values() if entry['version']==args.version]+list(lock['extensions'].values())
subjects=[];files=[]
for path in sorted(args.prefix.rglob('*')):
    if path.is_file():
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        name=str(path);subjects.append({'name':name,'digest':{'sha256':digest}})
        files.append({'SPDXID':'SPDXRef-File-'+digest,'fileName':name,'checksums':[{'algorithm':'SHA256','checksumValue':digest}],'licenseConcluded':'NOASSERTION','copyrightText':'NOASSERTION'})
# Duplicate identical files may share hashes; SPDX identifiers must remain unique.
for index,entry in enumerate(files):entry['SPDXID']='SPDXRef-File-'+str(index)
packages=[]
for index,source in enumerate(sources):
    packages.append({'SPDXID':'SPDXRef-Source-'+str(index),'name':source['url'].rsplit('/',1)[-1],'versionInfo':source['version'],'downloadLocation':source['url'],'filesAnalyzed':False,'checksums':[{'algorithm':'SHA256','checksumValue':source['sha256']}],'licenseConcluded':'NOASSERTION','licenseDeclared':source['license'],'copyrightText':'NOASSERTION'})
for index,line in enumerate((args.evidence/'build-dependencies.txt').read_text().splitlines()):
    name,version,architecture=line.split('\t')
    packages.append({'SPDXID':'SPDXRef-Native-'+str(index),'name':name,'versionInfo':version,'downloadLocation':'NOASSERTION','filesAnalyzed':False,'licenseConcluded':'NOASSERTION','licenseDeclared':'NOASSERTION','copyrightText':'NOASSERTION','externalRefs':[{'referenceCategory':'PACKAGE-MANAGER','referenceType':'purl','referenceLocator':f'pkg:deb/ubuntu/{name}@{version}?arch={architecture}&distro=resolute'}]})
epoch=int(os.environ.get('SOURCE_DATE_EPOCH','1790208000'))
created=datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
identity=hashlib.sha256(json.dumps(subjects,sort_keys=True).encode()).hexdigest()
sbom={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':'nakpanel-php-'+args.version+'-'+args.architecture,'documentNamespace':'https://nakpanel.invalid/spdx/'+identity,'creationInfo':{'created':created,'creators':['Tool: nakpanel-private-php-builder']},'packages':packages,'files':files,'relationships':[{'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':p['SPDXID']} for p in packages]}
(args.evidence/'sbom.spdx.json').write_text(json.dumps(sbom,indent=2,sort_keys=True)+'\n')
provenance={'_type':'https://in-toto.io/Statement/v1','subject':subjects,'predicateType':'https://slsa.dev/provenance/v1','predicate':{'buildDefinition':{'buildType':'https://nakpanel.invalid/build-types/native-private-php/v1','externalParameters':{'os_id':'ubuntu','version_id':'26.04','codename':'resolute','architecture':args.architecture,'php_version':args.version,'patches':lock['patches'],'builder_image_digest':os.environ.get('NAKPANEL_BUILDER_IMAGE_DIGEST'),'qualification':'candidate-only'},'internalParameters':{},'resolvedDependencies':[{'uri':s['url'],'digest':{'sha256':s['sha256']}} for s in sources]+[{'uri':'file:build-dependencies.txt','digest':{'sha256':hashlib.sha256((args.evidence/'build-dependencies.txt').read_bytes()).hexdigest()}}]},'runDetails':{'builder':{'id':os.environ.get('NAKPANEL_BUILDER_ID','unconfigured')},'metadata':{'invocationId':os.environ.get('NAKPANEL_BUILD_INVOCATION_ID',identity)}}}}
(args.evidence/'provenance.json').write_text(json.dumps(provenance,indent=2,sort_keys=True)+'\n')
