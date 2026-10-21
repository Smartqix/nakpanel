#!/usr/bin/env python3
"""Produce private, observed inputs for the existing disposable maintenance drill.

No production update, provider switch, version advance or guest adoption exists.
The canonical gate process is isolated and reaped before exclusive source handoff.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.request

# Keep ordinary CLI execution from creating local helper caches before the
# strict committed-source check. Unreviewed cache files remain disallowed.
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
_spec = importlib.util.spec_from_file_location('maintenance_contract', HERE/'sury-maintenance-drill.py')
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)
DRIVER = {'deploy/multipass/common.sh','deploy/multipass/qualification-artifacts.sh',
          'deploy/multipass/qualification_artifacts.py','deploy/release/verify.py','deploy/install/stage_bundle.py'}
OWNED = {'deploy/multipass/sury-maintenance-prepare.py','deploy/multipass/sury_maintenance_prepare_test.py',
         'deploy/multipass/sury_maintenance_prepare_test.go'}
FROZEN = DRIVER | M.QUALIFIER_FILES | OWNED | {
    'deploy/multipass/sury-maintenance-drill.py','deploy/multipass/sury-maintenance-verify.sh',
    'deploy/multipass/sury_maintenance_test.py','deploy/multipass/sury_maintenance_test.go',
    'deploy/multipass/ubuntu-platform-verify.sh','.github/workflows/ubuntu-hosted-qualification.yml',
    'deploy/install/platform.sh','deploy/install/sury-php-archive-keyring.gpg','deploy/install/dependencies.json'}
BASE = 'https://packages.sury.org/php/'
# The qualified Adminer install brings these Ubuntu dependency selectors. They
# are observed and preserved, never retained or reinstalled as Surý packages.
DISTRIBUTION_PHP = {f'php-{extension}':f'php8.5-{extension}' for extension in ('mysql','pgsql','sqlite3')}
APPLICATION_PHP = {'php8.5-pgsql'}
BASELINE_SUBSTAGES = {'signed-metadata','authenticated-indexes','package-inventory','exact-php-closure',
                     'candidate-origin-and-apt-plan','retained-package-archives','baseline-complete'}
FAILURE_CODES = {
    'installed PHP outside the qualified profile is unsupported':'unsupported-installed-php',
    'distribution PHP controls differ from the qualified layout':'invalid-distribution-php-controls',
    'preexisting PHP dpkg state is not clean':'unclean-installed-php',
    'installed PHP must match exactly one signed package row':'signed-runtime-row-mismatch',
    'profile PHP packages are missing':'missing-profile-php',
    'required installed PHP dependency is missing':'missing-runtime-dependency',
    'installed PHP exceeds the exact profile dependency closure':'excess-runtime-closure',
    'native gpgv did not authenticate exact provider metadata':'provider-signature-failed',
    'retained package budget exceeded':'package-budget-exceeded',
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def check_report(report, binding):
    M.require(report.get("qualification_scope") == "CURRENT_VERSION_ONLY" and report.get("excluded_gates") == ["real-upgrade"], "current-version qualification scope required")
    M.require(report.get('schema_version') == 1 and report.get('qualification_passed') is True and
              report.get('full_php_parity') is True and report.get('pending_gates') == [], 'complete current16 qualification is required')
    M.require(report.get('release') == '26.04' and report.get('architecture') == 'amd64' and
              report.get('profile') == 'ubuntu-26.04-sury' and report.get('php_provider') == 'sury', 'hosted Surý26 AMD64 source required')
    M.require(set(report.get('php_contract',[])) == set(M.MINORS) and len(report['php_contract']) == 3 and
              report.get('features',{}).get('database_manager_requested') is True, 'complete PHP and database-browser baseline required')
    for key in ('source_vm','run_token','release','architecture','profile','php_provider'):
        M.require(report.get(key) == binding[key], 'completed qualification source differs')
    gates=report.get('gates',[])
    M.require(len(gates)==len(M.GATES) and {g.get('name') for g in gates}==M.GATES and
              all(g.get('status')=='PASS' and type(g.get('exit_code')) is int and g['exit_code']==0 for g in gates), 'every canonical gate must pass')


def process_group_exists(group):
    try:
        os.killpg(group,0)
        return True
    except ProcessLookupError:
        return False


def stop_owned_process_group(child):
    # This group was created by this invocation with start_new_session=True.
    # No unrelated VM, shell session or process group is targeted.
    if process_group_exists(child.pid):
        try:os.killpg(child.pid,signal.SIGTERM)
        except ProcessLookupError:pass
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.wait(timeout=2)
    for _ in range(20):
        if not process_group_exists(child.pid):return True
        time.sleep(.05)
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    for _ in range(20):
        if not process_group_exists(child.pid):return True
        time.sleep(.05)
    return False


def run_canonical(argv, receipt, report_path, binding, env, source_proof=None):
    M.require(not Path(receipt).exists(), 'canonical execution receipt already exists')
    proof=dict(schema='nakpanel-canonical-execution-v1',source_binding={k:binding[k] for k in
               ('source_vm','run_token','release','architecture','profile','php_provider')},
               started_at=utc(),pid=None,process_group=None,exit_code=None,
               process_exited=False,process_group_empty=False,success=False,status='STARTED')
    if source_proof:proof.update(source_proof)
    M.write_private(receipt,proof)
    child=None
    starting=True
    pending_signal=None
    previous={number:signal.getsignal(number) for number in (signal.SIGINT,signal.SIGTERM)}
    def interrupted(number,frame):
        nonlocal pending_signal
        if starting:
            # Popen can have created a real new session before returning its
            # Python handle. Keep custody acquisition uninterrupted, then act
            # on the recorded cancellation with the actual owned PID/group.
            if pending_signal is None:pending_signal=number
            return
        raise SystemExit(128+number)
    for number in previous:signal.signal(number,interrupted)
    try:
        child=subprocess.Popen(argv,env=env,start_new_session=True)
        proof.update(pid=child.pid,process_group=child.pid)
        M.write_private(receipt,proof)
        starting=False
        if pending_signal is not None:raise SystemExit(128+pending_signal)
        code=child.wait()
        empty=not process_group_exists(child.pid)
        proof.update(exit_code=code,process_exited=True,process_group_empty=empty)
        M.require(empty,'canonical child process remains; no exclusive handoff')
        M.require(code==0,'canonical qualification process failed')
        report_bytes=Path(report_path).read_bytes()
        check_report(json.loads(report_bytes),binding)
        proof.update(success=True,status='PASS',qualification_report_sha256=M.digest(report_bytes))
        return proof
    except BaseException as error:
        # Cancellation must not orphan a newly isolated canonical process or
        # race the workflow's always-owned cleanup. Block repeat soft signals
        # only while terminating/reaping this invocation's own group.
        for number in previous:signal.signal(number,signal.SIG_IGN)
        proof.update(success=False,status='FAIL',error_type=type(error).__name__)
        if child is not None:
            proof.update(pid=child.pid,process_group=child.pid)
            try:proof['cleanup_group_empty']=stop_owned_process_group(child)
            except BaseException as cleanup_error:proof['cleanup_error_type']=type(cleanup_error).__name__
            proof.update(exit_code=child.returncode,process_exited=child.poll() is not None)
        raise
    finally:
        proof['finished_at']=utc()
        try:M.write_private(receipt,proof)
        finally:
            for number,handler in previous.items():signal.signal(number,handler)


def source_map(source, paths, run_id):
    commit=M.command(['git','-C',str(source),'rev-parse','HEAD']).stdout.strip()
    changes=M.command(['git','-C',str(source),'status','--porcelain','--untracked-files=all']).stdout.splitlines()
    M.require(all(line==' M README.md' for line in changes),'source has unreviewed changes')
    if changes:
        original=subprocess.run(['git','-C',str(source),'show',commit+':README.md'],capture_output=True,check=True).stdout
        M.require(re.fullmatch(r'[0-9]+',run_id or '') is not None and
                  (source/'README.md').read_bytes()==original+('\n<!-- hosted development qualification '+run_id+' -->\n').encode(),
                  'only the documented build marker may differ')
    mapping={name:M.digest((source/name).read_bytes()) for name in paths}
    M.check_frozen_checkout(source,mapping,commit)
    return commit,mapping


def check_indexes(release, compressed):
    M.require(set(compressed)=={'amd64','arm64'},'both architecture indexes must be authenticated')
    fields,_=M.release_body(release)
    M.require(fields.get('Suite')=='resolute' and fields.get('Codename')=='resolute','signed provider suite differs')
    result={}
    for architecture,value in compressed.items():
        M.check_index_packages(release,value,architecture,[])
        result[architecture]=list(M.deb822(lzma.decompress(value)))
    return result


def distribution_php_controls(installed, architecture):
    M.require(architecture in ('amd64','arm64'),'distribution PHP controls differ from the qualified layout')
    aliases={name:value for name,value in installed.items() if name in DISTRIBUTION_PHP}
    for name,value in aliases.items():
        target=DISTRIBUTION_PHP[name]
        M.require(type(value) is list and len(value)==4 and all(type(part) is str for part in value) and
                  0<len(value[0])<=256 and value[1:] == ['install ok installed','all','php-common, '+target] and
                  all(dependency in installed and len(installed[dependency])>=2 and installed[dependency][1]=='install ok installed'
                      for dependency in ('php-common',target)),
                  'distribution PHP controls differ from the qualified layout')
    return aliases


def bind_distribution_php_controls(installed, raw, architecture):
    # Match the second actual dpkg query to the original complete inventory;
    # neither a missing record nor an extra/duplicate row can be substituted.
    M.require(type(raw) is str and len(raw)<=8192,'distribution PHP controls differ from the qualified layout')
    expected=set(installed)&set(DISTRIBUTION_PHP);controls={}
    for line in raw.splitlines():
        fields=line.split('\t')
        M.require(len(fields)==5 and fields[0] in expected and fields[0] not in controls and
                  fields[1:3]==installed[fields[0]],'distribution PHP controls differ from the qualified layout')
        controls[fields[0]]=fields[1:]
    M.require(set(controls)==expected,'distribution PHP controls differ from the qualified layout')
    enriched=dict(installed,**controls)
    distribution_php_controls(enriched,architecture)
    return enriched


def package_layout(installed, direct, architecture):
    # This projection is safe to publish even before closure validation. Raw
    # versions, control fields and command/exception output stay private.
    names=[name.removesuffix(':'+architecture) for name in installed if name.startswith('php')]
    M.require(len(names)<=256 and len(direct)<=256 and
              all(type(name) is str and len(name)<=128 and re.fullmatch(r'php[a-z0-9+.-]*',name) for name in names+list(direct)),
              'PHP package layout exceeds bounded diagnostic schema')
    states={'installed':0,'residual_config':0,'other':0}
    for name,value in installed.items():
        if name.startswith('php'):
            state='installed' if value[1]=='install ok installed' else 'residual_config' if value[1]=='deinstall ok config-files' else 'other'
            states[state]+=1
    return dict(schema='nakpanel-sury-package-layout-v1',architecture=architecture,php_package_names=sorted(names),
                distribution_metapackages=sorted(set(installed)&set(DISTRIBUTION_PHP)),
                application_roots=sorted(set(installed)&APPLICATION_PHP),profile_required_packages=sorted(direct),state_counts=states)


def installed_closure(rows, installed, direct, architecture):
    aliases=distribution_php_controls(installed,architecture)
    M.require(all(not name.startswith('php') or M.PHP_NAME.fullmatch(name.removesuffix(':'+architecture))
                  or name in aliases
                  for name,value in installed.items() if value[1]!='deinstall ok config-files'),
              'installed PHP outside the qualified profile is unsupported')
    actual={name.removesuffix(':'+architecture):value for name,value in installed.items()
            if M.PHP_NAME.fullmatch(name.removesuffix(':'+architecture))}
    selected={}
    for name,value in actual.items():
        M.require(value[1]=='install ok installed','preexisting PHP dpkg state is not clean')
        candidates=[r for r in rows if r.get('Package')==name and r.get('Version')==value[0] and r.get('Architecture') in (architecture,'all')]
        M.require(len(candidates)==1,'installed PHP must match exactly one signed package row')
        selected[name]=candidates[0]
    M.require(set(direct)<=set(selected),'profile PHP packages are missing')
    # Follow PHP-only dependency edges from the actual profile. APT simulation
    # independently resolves version relations, virtuals and non-PHP libraries.
    reached=set(direct)|(set(selected)&APPLICATION_PHP); queue=list(reached)
    while queue:
        row=selected[queue.pop()]
        for relation in ((row.get('Depends') or '')+','+(row.get('Pre-Depends') or '')).split(','):
            alternatives=[re.match(r'\s*([a-z0-9][a-z0-9+.-]*)',part) for part in relation.split('|')]
            matches=[x[1] for x in alternatives if x and x[1] in selected]
            php_names=[x[1] for x in alternatives if x and M.PHP_NAME.fullmatch(x[1])]
            M.require(not php_names or matches or any(x and x[1] in installed for x in alternatives),
                      'required installed PHP dependency is missing')
            if matches and matches[0] not in reached:
                reached.add(matches[0]);queue.append(matches[0])
    M.require(reached==set(selected),'installed PHP exceeds the exact profile dependency closure')
    return [selected[name] for name in sorted(selected)]


def check_capacity(source_disk_bytes, free_bytes):
    M.require(type(source_disk_bytes) is int and source_disk_bytes>0 and
              free_bytes>=source_disk_bytes+2*2**30,'insufficient measured disk for cold retention plus 2GiB overhead')
    return dict(source_disk_bytes=source_disk_bytes,free_bytes=free_bytes,additional_reserve_bytes=2*2**30,status='PASS')


def download(url, path, *, expected=None, size=None, limit=64*2**20):
    M.require(url.startswith(BASE) and len(url)<4096,'unexpected provider URL')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as target,urllib.request.urlopen(url,timeout=60) as response:
        M.require(response.url.startswith('https://'),'provider redirected outside HTTPS')
        total=0
        while block:=response.read(2**20):
            total+=len(block);M.require(total<=limit,'provider artifact exceeds bounded size');target.write(block)
        target.flush();os.fsync(target.fileno())
    value=M.private_bytes(path)
    M.require((expected is None or M.digest(value)==expected) and (size is None or len(value)==size),'provider artifact hash/size differs')
    return value


class Producer:
    def __init__(self, source, private_root, execution, env, qualifier_source=None):
        self.source=Path(source).resolve();self.qualifier_source=Path(qualifier_source).resolve() if qualifier_source is not None else self.source;self.root=Path(private_root);self.execution=Path(execution);self.env=env
        M.require(self.root.is_absolute() and not self.root.exists(),'fresh absolute private preparation path required')
        parent=self.root.parent
        info=parent.lstat()
        M.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022 and parent.resolve()==parent,'unsafe private preparation parent')
        self.root.mkdir(mode=0o700)
        self.stage='host-inputs';self.substage=None;self.config={}

    def record(self,status='STARTED',failure_code=None):
        substage=self.substage if self.stage=='signed-provider-baseline' else None
        M.require(status in ('STARTED','PREPARED','PASS','FAIL') and
                  (substage is None or substage in BASELINE_SUBSTAGES) and
                  (failure_code is None or (status=='FAIL' and failure_code in FAILURE_CODES.values())),
                  'unsupported preparation diagnostic')
        M.write_private(self.root/'preparation.json',dict(schema='nakpanel-sury-maintenance-preparation-v1',status=status,
            stage=self.stage,substage=substage,failure_code=failure_code,
            source_vm=self.config.get('source_vm'),run_token=self.config.get('run_token'),
            genuine_version_advance=False,apt_version_rollback=False,updated_at=utc()))

    def baseline_stage(self,substage):
        M.require(substage in BASELINE_SUBSTAGES,'unsupported preparation diagnostic')
        self.substage=substage;self.record()

    def guest(self,args,**kwargs):
        M.host_identity(self.config,self.source,self.env)
        return M.command(['multipass','exec',self.config['source_vm'],'--','sudo',*args],env=self.env,**kwargs)

    def prepare(self):
        self.record()
        commit,mapping=source_map(self.source,FROZEN,self.env.get('GITHUB_RUN_ID',''))
        qualifier_commit,qualifier_mapping=(commit,mapping) if self.qualifier_source==self.source else source_map(self.qualifier_source,FROZEN,self.env.get('GITHUB_RUN_ID',''))
        report_dir=Path(self.env['NAKPANEL_CELL_REPORT_DIR'])
        report_bytes=(report_dir/'report.json').read_bytes();report=json.loads(report_bytes)
        binding=dict(source_vm=self.env['NAKPANEL_MULTIPASS_VM'],run_token=self.env['NAKPANEL_RUN_TOKEN'],release='26.04',
                     architecture='amd64',profile='ubuntu-26.04-sury',php_provider='sury')
        check_report(report,binding)
        execution=json.loads(M.private_bytes(self.execution))
        M.require(execution.get('schema')=='nakpanel-canonical-execution-v1' and execution.get('success') is True and
                  execution.get('process_exited') is True and execution.get('process_group_empty') is True and
                  type(execution.get('exit_code')) is int and execution['exit_code']==0 and execution.get('source_binding')==binding and
                  execution.get('qualification_report_sha256')==M.digest(report_bytes) and not process_group_exists(execution['process_group']),
                  'canonical process completion/source/report proof differs')
        M.require(execution.get('runtime_commit')==commit and execution.get('qualifier_source_sha256')==mapping,
                  'canonical process did not execute the same frozen qualifier source')
        bundle=Path(self.env['NAKPANEL_RELEASE_BUNDLE']);manifest_bytes=(bundle/'manifest.json').read_bytes();manifest=json.loads(manifest_bytes)
        M.require(manifest['commit']==commit and manifest['architecture']=='amd64' and type(manifest['development']) is bool,'runtime must be the actual selected driver commit')
        config=dict(binding,operation=M.MODE,app_version=manifest['version'],runtime_commit=commit,qualifier_commit=qualifier_commit,
            manifest_sha256=M.digest(manifest_bytes),installed_binary_sha256={name:manifest['files']['bin/'+name] for name in ('panel','agent','panelctl')},
            allow_development=manifest['development'],maintenance_id='hosted-maintenance-'+binding['run_token'],
            retention_snapshot='maintenance-sury-'+binding['run_token'],driver_source=str(self.source),qualifier_source=str(self.qualifier_source),
            driver_source_sha256={name:mapping[name] for name in DRIVER},qualifier_source_sha256=qualifier_mapping,
            qualifier_files_sha256={name:qualifier_mapping[name] for name in M.QUALIFIER_FILES},
            qualifier_wrapper_sha256=qualifier_mapping['deploy/multipass/internal-tools-verify.sh'],qualifier_helper_sha256=qualifier_mapping['deploy/multipass/roundcube-send-read.py'],
            maintenance_helper_sha256=qualifier_mapping['deploy/multipass/sury-maintenance-drill.py'],bundle=str(bundle),
            public_key=self.env['NAKPANEL_RELEASE_PUBLIC_KEY'],public_key_sha256=M.digest(Path(self.env['NAKPANEL_RELEASE_PUBLIC_KEY']).read_bytes()),
            signature_sha256=M.digest((bundle/'manifest.sig').read_bytes()),ownership_directory=self.env['NAKPANEL_OWNERSHIP_DIR'],
            cell_report_directory=str(report_dir),evidence_directory=str(self.root/'drill'),baseline_directory=str(self.root/'baseline'))
        self.config=config
        verify=[sys.executable,str(self.source/'deploy/release/verify.py'),'--bundle',str(bundle),'--public-key',config['public_key'],
                '--version',config['app_version'],'--architecture','amd64']
        if config['allow_development']:verify.append('--allow-development')
        M.command(verify)
        M.host_record(config);M.host_identity(config,self.source,self.env)
        refs={}
        def receipt(name,value):
            path=self.root/(name+'.json');M.write_private(path,value);refs[name]={'path':str(path),'sha256':M.digest(M.private_bytes(path))};return refs[name]['sha256']
        config['qualification_report_sha256']=receipt('qualification_report',report)
        self.stage='actual-roundcube-baseline';self.record()
        output=self.root/'roundcube_receipt.json';started=utc()
        result=M.command(['bash',str(self.qualifier_source/'deploy/multipass/internal-tools-verify.sh'),'--roundcube-only'],
                         env=dict(self.env,NAKPANEL_INTERNAL_TOOLS_RECEIPT=str(output)),timeout=600,check=False)
        M.write_private(self.root/'roundcube-baseline.log',(result.stdout+result.stderr).encode())
        M.require(result.returncode==0,'actual Roundcube baseline failed; uncertain sends are not retried')
        envelope=json.loads(M.private_bytes(output))
        config['roundcube_receipt_sha256']=M.digest(M.private_bytes(output));refs['roundcube_receipt']={'path':str(output),'sha256':config['roundcube_receipt_sha256']}
        outer={k:config[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider','runtime_commit','qualifier_commit')}
        outer.update(schema='nakpanel-roundcube-supplement-execution-v1',success=True,exit_code=0,
                     qualifier_files_sha256=config['qualifier_files_sha256'],envelope_sha256=config['roundcube_receipt_sha256'],started_at=started,finished_at=utc())
        M.check_roundcube_execution(outer,config,envelope)
        config['roundcube_execution_sha256']=receipt('roundcube_execution_receipt',outer)
        self.stage='cold-retention';self.record()
        retention=self.cold_retention()
        config['retention_receipt_sha256']=receipt('retention_receipt',retention)
        self.stage='signed-provider-baseline';self.record()
        self.collect_baseline(receipt)
        handoff={k:config[k] for k in M.BINDING}
        handoff.update(schema='nakpanel-sury-maintenance-handoff-v1',exclusive_source_handoff=True,allowed_operations=[M.MODE],
            **{k:config[k] for k in ('qualification_report_sha256','roundcube_receipt_sha256','roundcube_execution_sha256','retention_receipt_sha256')})
        receipt('exclusive_handoff',handoff)
        M.validate_authorization(config,report,envelope,retention,handoff)
        M.require(not process_group_exists(execution['process_group']),'canonical child appeared before exclusive handoff')
        config['references']=refs
        M.write_private(self.root/'spec.json',config)
        self.stage='maintenance-handoff';self.record('PREPARED')
        return self.root/'spec.json'

    def collect_baseline(self,receipt):
        config=self.config;baseline=Path(config['baseline_directory']);baseline.mkdir(mode=0o700)
        self.baseline_stage('signed-metadata')
        release=download(BASE+'dists/resolute/InRelease',baseline/'InRelease',limit=2**20)
        key=self.guest(['sha256sum','/usr/share/keyrings/nakpanel-sury-php.gpg']).stdout.split()[0]
        M.require(key==M.KEY_SHA,'actual guest provider key differs')
        signed=self.guest(['gpgv','--status-fd','1','--keyring','/usr/share/keyrings/nakpanel-sury-php.gpg','-'],data=release.decode(),check=False)
        valid=[line.split() for line in signed.stdout.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        M.require(signed.returncode==0 and valid and all(row[-1]==M.FINGERPRINT for row in valid) and
                  not any('[GNUPG:] '+bad+' ' in signed.stdout for bad in ('BADSIG','ERRSIG','EXPSIG','EXPKEYSIG','REVKEYSIG')),'native gpgv did not authenticate exact provider metadata')
        native=dict(native_gpgv=True,exit_code=0,vm=config['source_vm'],run_token=config['run_token'],release='26.04',architecture='amd64',
                    key_sha256=key,inrelease_sha256=M.digest(release),validsig_fingerprint=M.FINGERPRINT,guest_mutation=False,package_transaction=False,
                    verified_at=utc(),status_sha256=M.digest(signed.stdout.encode()),stderr_sha256=M.digest(signed.stderr.encode()))
        M.write_private(baseline/'native-gpgv.stdout',signed.stdout.encode());M.write_private(baseline/'native-gpgv.stderr',signed.stderr.encode())
        receipt('native_gpgv_receipt',native)
        self.baseline_stage('authenticated-indexes')
        compressed={arch:download(BASE+'dists/resolute/main/binary-'+arch+'/Packages.xz',baseline/(arch+'-Packages.xz')) for arch in ('amd64','arm64')}
        rows=check_indexes(release,compressed)
        self.baseline_stage('package-inventory')
        raw=self.guest(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Status}\n']).stdout
        installed={p[0]:p[1:] for line in raw.splitlines() if len(p:=line.split('\t'))==3}
        direct_script='set -euo pipefail; source "$1"; NAKPANEL_INTERNAL_PHP_VERSION=8.5; NAKPANEL_HOSTING_PHP_VERSIONS=(8.3 8.4 8.5); nakpanel_php_packages'
        direct=M.command(['bash','-c',direct_script,'_',str(self.source/'deploy/install/platform.sh')]).stdout.splitlines()
        layout=package_layout(installed,direct,'amd64')
        layout.update({key:config[key] for key in ('source_vm','run_token','runtime_commit','qualifier_commit','profile','php_provider')})
        M.write_private(self.root/'package-layout.json',layout)
        present=sorted(set(installed)&set(DISTRIBUTION_PHP))
        controls=self.guest(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Status}\t${Architecture}\t${Depends}\n',*present]).stdout if present else ''
        installed=bind_distribution_php_controls(installed,controls,'amd64')
        self.baseline_stage('exact-php-closure')
        packages=installed_closure(rows['amd64'],installed,direct,'amd64')
        M.require(sum(int(row['Size']) for row in packages)<=256*2**20,'retained package budget exceeded')
        versions={row['Package']:row['Version'] for row in packages}
        self.baseline_stage('candidate-origin-and-apt-plan')
        for name,version in versions.items():
            M.check_candidate(self.guest(['apt-cache','policy',name]).stdout,version)
        plan=self.guest(['apt-get','--simulate','--no-remove','--reinstall','--fix-broken','install',
                         *[name+'='+version for name,version in sorted(versions.items())]],timeout=600)
        M.check_apt_plan(plan.stdout,versions,set(versions))
        self.baseline_stage('retained-package-archives')
        retained=baseline/'retained-baseline';retained.mkdir(mode=0o700);retained=retained/'amd64';retained.mkdir(mode=0o700)
        for row in packages:
            # Filename safety is checked against the authenticated index before
            # it is used as either a URL path or a private destination.
            M.check_index_packages(release,compressed['amd64'],'amd64',[row])
            target=retained/Path(row['Filename']).name
            download(BASE+row['Filename'],target,expected=row['SHA256'],size=int(row['Size']))
            row['retained_file']=str(target)
        inventory=dict(state='AUTHENTICATED_CURRENT_BASELINE_ONLY_NO_VERSION_ADVANCE',provider=BASE,suite='resolute',source_commit=config['runtime_commit'],
            profile=config['profile'],derivation=dict(profile_required_packages=direct,
                application_roots=layout['application_roots'],unchanged_distribution_metapackages=layout['distribution_metapackages'],
                platform_sh_sha256=M.digest((self.source/'deploy/install/platform.sh').read_bytes())),
            trust=dict(native_gpgv=True,inrelease_sha256=M.digest(release),key_sha256=M.KEY_SHA),
            architectures={'amd64':dict(packages=packages)},both_architecture_indexes_verified=True)
        receipt('baseline_inventory',inventory)
        _,checksums=M.release_body(release)
        M.write_private(self.root/'package-baseline.json',dict(schema='nakpanel-sury-authenticated-baseline-v1',source_vm=config['source_vm'],
            run_token=config['run_token'],runtime_commit=config['runtime_commit'],provider=BASE,suite='resolute',architecture='amd64',
            genuine_version_advance=False,native_gpgv_receipt_sha256=M.digest(M.private_bytes(self.root/'native_gpgv_receipt.json')),
            inrelease_sha256=M.digest(release),indexes={name:dict(sha256=value[0],size=value[1]) for name,value in checksums.items()
                if name in {f'main/binary-{arch}/Packages{suffix}' for arch in ('amd64','arm64') for suffix in ('','.xz')}},
            packages=[{key:row[key] for key in ('Package','Version','Architecture','Filename','SHA256','Size')} for row in packages]))
        self.baseline_stage('baseline-complete')

    def cold_retention(self):
        config=self.config
        # Read actual root-disk size, rather than assuming the workflow's32G
        # declaration. Unsupported block layouts refuse before any service stop.
        probe=self.guest(['bash','-c',
            'set -euo pipefail; dev=$(findmnt -n -o SOURCE /); parent=$(lsblk -nro PKNAME "$dev"); '
            '[[ "$parent" =~ ^[a-zA-Z0-9]+$ ]]; blockdev --getsize64 "/dev/$parent"']).stdout.strip()
        capacity=check_capacity(int(probe),min(shutil.disk_usage('/var/snap/multipass/common').free,shutil.disk_usage(self.root).free))
        M.write_private(self.root/'capacity.json',capacity)
        M.host_record(config);M.host_identity(config,self.source,self.env)
        self.guest(['bash','-c','set -euo pipefail; systemctl is-active --quiet nakpanel.service; systemctl is-active --quiet nakpanel-agent.service; systemctl stop nakpanel.service nakpanel-agent.service; sync'])
        M.command(['multipass','stop',config['source_vm']],env=self.env,timeout=300)
        cold=json.loads(M.command(['multipass','info',config['source_vm'],'--format','json'],env=self.env).stdout)
        M.require(cold.get('errors')==[] and set(cold.get('info',{}))=={config['source_vm']} and
                  cold['info'][config['source_vm']]['state']=='Stopped','snapshot source is not proven cold')
        M.command(['multipass','snapshot',config['source_vm'],'--name',config['retention_snapshot'],
                   '--comment','Owned qualified same-version PHP maintenance retention'],env=self.env,timeout=600)
        raw=M.command(['multipass','info',config['source_vm']+'.'+config['retention_snapshot'],'--format','json'],env=self.env).stdout
        metadata=json.loads(raw)['info'][config['source_vm']]['snapshots'][config['retention_snapshot']]
        retention={k:config[k] for k in M.BINDING}
        retention.update(schema='nakpanel-sury-maintenance-retention-v1',status='PASS',snapshot_name=config['retention_snapshot'],
            snapshot_id=config['source_vm']+'.'+config['retention_snapshot'],snapshot_info_sha256=M.digest(M.canonical(metadata)),
            cold_snapshot=True,running_revalidated=False,ownership_verified=True)
        M.check_snapshot_info(json.loads(raw),config,retention)
        M.write_private(self.root/'snapshot-info.json',json.loads(raw))
        M.command(['multipass','start',config['source_vm']],env=self.env,timeout=300)
        M.command(['bash','-c','set -euo pipefail; source "$1"; wait_for_cloud_init "$2"','_',str(self.source/'deploy/multipass/common.sh'),config['source_vm']],env=self.env,timeout=300)
        M.host_record(config);M.host_identity(config,self.source,self.env)
        self.guest(['systemctl','is-active','--quiet','nakpanel.service','nakpanel-agent.service'])
        retention['running_revalidated']=True
        return retention


def publish(root,destination):
    destination.mkdir(mode=0o700,exist_ok=False)
    for name in ('preparation.json','capacity.json','roundcube_execution_receipt.json','retention_receipt.json',
                 'native_gpgv_receipt.json','package-baseline.json','package-layout.json'):
        path=root/name
        if path.exists():M.write_private(destination/name,json.loads(M.private_bytes(path)))
    drill=root/'drill'
    # Private specs, credentials, package archives, source/config inventories
    # and arbitrary command output never enter the always-upload directory.
    for name in ('result.json','recovery.json','reboot-1.json','reboot-2.json'):
        path=drill/name
        if path.exists():
            value=json.loads(M.private_bytes(path));value.pop('diagnostic',None)
            M.write_private(destination/name,value)
    for phase in ('recovered','reboot-1','reboot-2'):
        path=drill/('roundcube-'+phase+'.execution.json')
        if path.exists():M.write_private(destination/path.name,json.loads(M.private_bytes(path)))


def check_result(result,binding):
    M.require(result.get('schema')=='nakpanel-sury-maintenance-result-v1' and result.get('status')=='PASS' and
              result.get('operation')==M.MODE and all(result.get(k)==binding[k] for k in ('source_vm','run_token','runtime_commit','qualifier_commit')),
              'actual maintenance result/source differs')
    M.require(all(result.get(k) is True for k in ('same_version_delivery','failed_configuration_recovery','two_reboots_verified')) and
              all(result.get(k) is False for k in ('genuine_version_advance','apt_version_rollback','application_rollback')) and
              type(result.get('roundcube_send_read_steps')) is int and result['roundcube_send_read_steps']==3 and
              type(result.get('reboots')) is list and len(result['reboots'])==2 and len(set(result['reboots']))==2,
              'actual same-version recovery/two-reboot/three-flow result is incomplete')


def record_request(env):
    cell=Path(env['NAKPANEL_CELL_REPORT_DIR']);path=cell/'sury-maintenance-request.json'
    M.require(not path.exists(),'maintenance coverage request already exists')
    report_bytes=(cell/'report.json').read_bytes();report=json.loads(report_bytes)
    M.require(report.get('qualification_passed') is True and report['source_vm']==env['NAKPANEL_MULTIPASS_VM'] and
              report['run_token']==env['NAKPANEL_RUN_TOKEN'],'completed owned canonical report required')
    manifest_bytes=(Path(env['NAKPANEL_RELEASE_BUNDLE'])/'manifest.json').read_bytes();manifest=json.loads(manifest_bytes)
    M.require(manifest_bytes==(cell/'release-manifest.json').read_bytes(),'canonical selected manifest differs')
    requested=report['release']=='26.04' and report['php_provider']=='sury' and env['NAKPANEL_VERIFY_SURY_MAINTENANCE']=='1'
    value={k:report[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider')}
    value.update(schema='nakpanel-sury-maintenance-coverage-v1',requested=requested,status='PENDING' if requested else 'NOT_REQUESTED',
        app_version=manifest['version'],runtime_commit=manifest['commit'],qualifier_commit=manifest['commit'],manifest_sha256=M.digest(manifest_bytes),
        installed_binary_sha256={name:manifest['files']['bin/'+name] for name in ('panel','agent','panelctl')},
        qualification_report_sha256=M.digest(report_bytes),genuine_version_advance=False)
    M.write_private(path,value)
    return path,value


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['qualify','request','prepare'])
    parser.add_argument('--execution-receipt',type=Path)
    parser.add_argument('--private-root',type=Path)
    parser.add_argument('--driver-source',type=Path)
    args=parser.parse_args()
    M.require(args.driver_source is None or args.operation=='prepare','separate qualifier/driver source is only supported by prepare')
    env=os.environ.copy()
    if args.operation=='request':
        record_request(env)
        return
    M.require(args.execution_receipt is not None,'explicit canonical execution receipt required')
    binding=dict(source_vm=env['NAKPANEL_MULTIPASS_VM'],run_token=env['NAKPANEL_RUN_TOKEN'],release='26.04',architecture='amd64',profile='ubuntu-26.04-sury',php_provider='sury')
    if args.operation=='qualify':
        commit,mapping=source_map(SOURCE,FROZEN,env.get('GITHUB_RUN_ID',''))
        run_canonical(['bash',str(SOURCE/'deploy/multipass/ubuntu-platform-verify.sh')],args.execution_receipt,
                      Path(env['NAKPANEL_CELL_REPORT_DIR'])/'report.json',binding,env,
                      dict(runtime_commit=commit,qualifier_source_sha256=mapping))
        return
    M.require(args.private_root is not None,'prepare requires an explicit fresh private root')
    producer=Producer(SOURCE,args.private_root,args.execution_receipt,env) if args.driver_source is None else Producer(args.driver_source,args.private_root,args.execution_receipt,env,qualifier_source=SOURCE)
    try:
        spec=producer.prepare()
        result=M.command(['bash',str(producer.qualifier_source/'deploy/multipass/sury-maintenance-verify.sh'),'same-version',str(spec)],env=env,timeout=3600,check=False)
        M.write_private(producer.root/'controller.log',(result.stdout+result.stderr).encode())
        M.require(result.returncode==0,'maintenance controller failed; inspect sanitized retained evidence')
        observed=json.loads(M.private_bytes(producer.root/'drill'/'result.json'))
        check_result(observed,producer.config)
        coverage_path=Path(env['NAKPANEL_CELL_REPORT_DIR'])/'sury-maintenance-request.json'
        coverage=json.loads(M.private_bytes(coverage_path))
        M.require(coverage.get('requested') is True and coverage.get('status')=='PENDING','explicit pending maintenance request required')
        M.bound(coverage,producer.config)
        coverage.update(status='PASS',qualifier_commit=producer.config['qualifier_commit'],result_sha256=M.digest(M.private_bytes(producer.root/'drill'/'result.json')),
                        database_manager_postchecks='actual-fastcgi-health; canonical-restricted-browser-baseline')
        M.write_private(coverage_path,coverage)
        producer.stage='complete';producer.record('PASS')
    except Exception as error:
        # Only exact locally defined messages map to public reason codes.
        # Arbitrary exceptions and guest output are never copied to receipts.
        producer.record('FAIL',failure_code=FAILURE_CODES.get(str(error)) if type(error) is ValueError else None)
        coverage_path=Path(env['NAKPANEL_CELL_REPORT_DIR'])/'sury-maintenance-request.json'
        if coverage_path.exists():
            coverage=json.loads(M.private_bytes(coverage_path));coverage['status']='FAIL'
            if producer.config.get('qualifier_commit'):coverage['qualifier_commit']=producer.config['qualifier_commit']
            M.write_private(coverage_path,coverage)
        raise
    finally:
        publish(producer.root,Path(env['NAKPANEL_CELL_REPORT_DIR'])/'sury-maintenance')


if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print('Surý maintenance preparation failed: '+type(error).__name__,file=sys.stderr)
        sys.exit(1)
