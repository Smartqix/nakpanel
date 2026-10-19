#!/usr/bin/env python3
"""Guest-side real assertions for the owned forward-migration fixture.

Input, including fixture credentials, arrives only on stdin. Results contain
hashes/public observations. This file is run by the fixture driver, not a daemon.
"""
import hashlib
from html.parser import HTMLParser
import pwd
import grp
import tempfile
import http.cookiejar
import imaplib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def command(args, data=None, env=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, env=env, timeout=600)
    if result.returncode:
        raise RuntimeError('guest operation failed: ' + args[0])
    return result.stdout.strip()


def pg(sql):
    return command(['runuser', '-u', 'postgres', '--', 'psql', '-Atq', '-d', 'nakpanel', '-c', sql])


def maria(sql, database=None, user=None, password=None):
    args = ['mariadb', '--default-character-set=utf8mb4', '-N', '-B']
    environment = None
    if user:
        args += ['--user=' + user]
        environment = dict(os.environ, MYSQL_PWD=password)
    if database:
        args.append(database)
    return command(args + ['-e', sql], env=environment)


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def cli(*args):
    return command(['runuser', '-u', 'nakpanel', '--', 'env',
                    'NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable',
                    'NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock',
                    'NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json',
                    'panelctl', '--actor', 'forward-fixture'] + list(args))


def wait(query, expected, seconds=300):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if pg(query) == expected:
            return
        time.sleep(2)
    raise RuntimeError('fixture did not converge before deadline')


def login(c):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    # Loopback bootstrap follows the existing phase verifiers; independent
    # certificate/hostname checks are mandatory after fixture certificates exist.
    opener.open('https://127.0.0.1:7443/login', urllib.parse.urlencode(
        {'email': c['admin_email'], 'password': c['admin_password']}).encode(), timeout=30).read()
    token = next((cookie.value for cookie in jar if cookie.name == 'nakpanel_session'), None)
    if not token:
        raise RuntimeError('fixture administrator login failed')
    csrf = hashlib.sha256(('nakpanel-csrf-v1:' + token).encode()).hexdigest()

    def post(path, values):
        request = urllib.request.Request('https://127.0.0.1:7443/' + path,
            data=urllib.parse.urlencode(values,doseq=True).encode(), headers={'X-Nakpanel-CSRF': csrf})
        response = opener.open(request, timeout=60)
        if response.status not in (200, 202, 303):
            raise RuntimeError('fixture API mutation failed')
        response.read()
    post.get=lambda path:opener.open('https://127.0.0.1:7443/'+path,timeout=60).read().decode()
    return post


def discover(c):
    site = c.get('site_id') or pg("SELECT id FROM sites WHERE domain='phase30-managed.test'")
    if not str(site).isdigit():
        raise RuntimeError('run the real phase30 managed-site/worker fixture first, or supply site_id')
    c['site_id'] = int(site)
    details = json.loads(pg("SELECT json_build_object('domain',s.domain,'username',s.username,'subscription_id',s.subscription_id) FROM sites s WHERE id=" + str(site)))
    c.update(details)
    worker = c.get('worker_id') or pg("SELECT w.id FROM php_workers w JOIN php_applications a ON a.id=w.application_id WHERE a.site_id=" + str(site) + " AND w.desired_state='running' ORDER BY w.id LIMIT 1")
    if not str(worker).isdigit():
        raise RuntimeError('a real desired-running managed PHP worker is required')
    c['worker_id'] = int(worker)
    version=pg('SELECT a.php_version FROM php_workers w JOIN php_applications a ON a.id=w.application_id WHERE w.id='+str(c['worker_id'])+' AND a.site_id='+str(c['site_id']))
    if version not in ('8.3','8.4','8.5'):raise RuntimeError('managed fixture worker has missing or unsupported PHP identity')
    c['worker_php_version']=version
    return c


def rootless(c, *args):
    base = '/var/lib/nakpanel/containers/sub-' + str(c['subscription_id'])
    runtime = '/run/nakpanel-containers/sub-' + str(c['subscription_id'])
    return command(['runuser', '-u', c['username'], '--', 'env', 'HOME=' + base + '/home',
                    'XDG_DATA_HOME=' + base + '/data', 'XDG_CONFIG_HOME=' + base + '/config',
                    'XDG_RUNTIME_DIR=' + runtime, 'TMPDIR=' + runtime, 'podman'] + list(args))



def subordinate_row(username, path):
    rows = [line for line in Path(path).read_text().splitlines() if line.startswith(username + ':')]
    if len(rows) > 1:
        raise ValueError('multiple source subordinate ranges require a separate fixture design')
    return rows[0] if rows else ''


def install_target_identities(c, root=Path('/')):
    # Plan every name/numeric/range collision before groupadd/useradd or writes.
    users = c['baseline']['identities']
    passwd = {u.pw_name:u for u in pwd.getpwall()}
    groups = {g.gr_name:g for g in grp.getgrall()}
    names, uids, gids = set(), set(), set()
    for user in users:
        n,uid,gid = user['name'],user['uid'],user['gid']
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',n) or n in ('root','nobody','nakpanel') or not isinstance(uid,int) or not isinstance(gid,int) or not 0 < uid < 2**31 or not 0 < gid < 2**31:
            raise ValueError('managed target identity must have safe nonroot numeric IDs')
        if n in names or uid in uids or gid in gids:
            raise ValueError('archived managed identity collision')
        names.add(n);uids.add(uid);gids.add(gid)
        if (n in passwd and (passwd[n].pw_uid != uid or passwd[n].pw_gid != gid)) or any(u.pw_uid == uid and u.pw_name != n for u in passwd.values()):
            raise ValueError('target user identity collision')
        if (n in groups and groups[n].gr_gid != gid) or any(g.gr_gid == gid and g.gr_name != n for g in groups.values()):
            raise ValueError('target group identity collision')
    replacements = {}
    for field in ('subuid','subgid'):
        path = root/'etc'/field
        existing = path.read_text().splitlines() if path.exists() else []
        retained = [line for line in existing if line.split(':',1)[0] not in names]
        incoming = [u[field] for u in users if u.get(field)]
        intervals = []
        for line in retained + incoming:
            if not line or line.startswith('#'): continue
            parts = line.split(':')
            if len(parts)!=3 or not parts[1].isdigit() or not parts[2].isdigit() or int(parts[1])<1 or int(parts[2])<1 or int(parts[1])+int(parts[2])>2**32:
                raise ValueError('invalid subordinate identity range')
            if line in incoming and parts[0] not in names:
                raise ValueError('archived subordinate identity name mismatch')
            start,end=int(parts[1]),int(parts[1])+int(parts[2])
            for owner,prior_start,prior_end,is_incoming in intervals:
                if (line in incoming or is_incoming) and max(start,prior_start)<min(end,prior_end):
                    raise ValueError('target subordinate range overlap')
            intervals.append((parts[0],start,end,line in incoming))
        for user in users:
            if user.get(field) and not user[field].startswith(user['name']+':'):
                raise ValueError('archived subordinate identity name mismatch')
        replacements[path]='\n'.join(retained+incoming)+('\n' if retained+incoming else '')
    for user in users:
        n,uid,gid=user['name'],user['uid'],user['gid']
        if n not in groups: command(['groupadd','--gid',str(gid),n])
        if n not in passwd:
            command(['useradd','--system','--no-user-group','--no-create-home','--uid',str(uid),'--gid',str(gid),'--home-dir','/home/'+n,'--shell','/usr/sbin/nologin',n])
        actual=pwd.getpwnam(n)
        if actual.pw_uid!=uid or actual.pw_gid!=gid: raise ValueError('created target identity differs from archive')
    for path,text in replacements.items():
        # Atomic replacement removes automatic/stale ranges for managed names;
        # unrelated entries retain their original ordering and bytes.
        descriptor,temporary=tempfile.mkstemp(prefix='.'+path.name+'-forward-',dir=path.parent)
        try:
            os.fchmod(descriptor,0o644)
            with os.fdopen(descriptor,'w') as out: out.write(text)
            os.replace(temporary,path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
    return {'managed_identities':len(users)}


def cache_target_images(c):
    install_target_identities(c)
    for image in c['images']:
        base='/var/lib/nakpanel/containers/sub-'+str(image['subscription_id'])
        runtime='/run/nakpanel-containers/sub-'+str(image['subscription_id'])
        for path in (base+'/home',base+'/data',base+'/config',runtime):
            command(['install','-d','-m','0700','-o',image['username'],'-g',image['username'],path])
        rootless(image,'pull',image['image_ref'])
    if c.get('valkey_image'): command(['podman','pull',c['valkey_image']])
    return {'immutable_image_caches':len(c['images'])}


def image_inventory():
    rows = json.loads(pg("SELECT COALESCE(json_agg(row_to_json(q)),'[]'::json) FROM (SELECT DISTINCT a.subscription_id,s.username,a.image_ref FROM application_instances a JOIN subscription_system_accounts s ON s.subscription_id=a.subscription_id WHERE a.runtime='oci' AND NOT a.delete_requested ORDER BY a.subscription_id,a.image_ref) q"))
    for row in rows:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}', row['image_ref']):
            raise RuntimeError('every restored OCI instance must use an immutable image reference')
        row['digest'] = rootless(row,'image','inspect','--format','{{.Digest}}',row['image_ref'])
        row['image_id'] = rootless(row,'image','inspect','--format','{{.Id}}',row['image_ref'])
        if not row['digest'] or not row['image_id']: raise RuntimeError('actual source OCI image observation missing')
    return rows


def managed_writers():
    result = []
    for kind in ('service','timer'):
        lines = command(['systemctl','list-units','--type='+kind,'--all','--no-legend','--plain']).splitlines()
        result += [line.split()[0] for line in lines if line.split() and re.match(r'(nakpanel-(php-worker@|php-fpm@|app-|valkey|task-)|php[0-9].*-fpm|cron\.service)',line.split()[0])]
    return sorted(set(result))


def roundcube_preflight(c, config_dir=Path('/etc/roundcube')):
    """Inspect literals and SQLite read-only; never source credential-bearing PHP."""
    allowed = {'/var/lib/roundcube/roundcube.sqlite', '/var/lib/roundcube/db/roundcube',
               '/var/lib/dbconfig-common/sqlite3/roundcube/roundcube'}
    selected = None
    for name in ('debian-db-roundcube.php', 'debian-db.php'):
        config = config_dir / name
        if not config.exists(): continue
        text = config.read_text()
        if name == 'debian-db-roundcube.php':
            match = re.search(r"(?m)^\s*\$config\[['\"]db_dsnw['\"]\]\s*=\s*['\"]([^'\"\r\n]*)['\"]\s*;", text)
            if not match: continue
            if not match[1].startswith('sqlite:'):
                raise RuntimeError('Roundcube configured non-SQLite storage is unsupported for forward migration; preserve the legacy database separately')
            selected = '/' + match[1][len('sqlite:'):].lstrip('/')
        else:
            values = dict(re.findall(r"(?m)^\s*\$(dbtype|dbbasepath|basepath|dbname)\s*=\s*['\"]([^'\"\r\n]*)['\"]\s*;", text))
            if not values.get('dbtype'): continue
            if values['dbtype'] not in ('sqlite','sqlite3'):
                raise RuntimeError('Roundcube configured non-SQLite storage is unsupported for forward migration; preserve the legacy database separately')
            selected = str(Path(values.get('dbbasepath') or values.get('basepath','')) / values.get('dbname',''))
        break
    if selected not in allowed:
        raise RuntimeError('forward migration requires an explicitly configured supported Roundcube SQLite database')
    database = Path(selected)
    if not database.is_file() or database.is_symlink():
        raise RuntimeError('configured Roundcube SQLite database must be a regular existing file')
    with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True) as connection:
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('Roundcube SQLite source integrity check failed')
    return {'roundcube_sqlite_path': selected, 'roundcube_storage_preflight': 'sqlite-readonly'}


class PlanEditor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True);self.forms=[];self.current=None;self.select=None;self.option=None;self.textarea=None
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='form':
            self.current=[] if a.get('action')=='/plans' and a.get('method','').lower()=='post' else None
        if self.current is None:return
        if tag=='input' and a.get('name') and 'disabled' not in a:
            kind=a.get('type','text').lower()
            if kind not in ('button','submit','reset','file') and (kind not in ('radio','checkbox') or 'checked' in a):self.current.append((a['name'],a.get('value','on' if kind in ('radio','checkbox') else '')))
        elif tag=='textarea' and a.get('name') and 'disabled' not in a:self.textarea=[a['name'],'']
        elif tag=='select' and a.get('name') and 'disabled' not in a:self.select=[a['name'],'multiple' in a,[]]
        elif tag=='option' and self.select is not None:self.option=[a.get('value'),'', 'selected' in a,'disabled' in a]
    def handle_data(self,data):
        if self.textarea is not None:self.textarea[1]+=data
        if self.option is not None:self.option[1]+=data
    def handle_endtag(self,tag):
        if self.current is None:return
        if tag=='textarea' and self.textarea is not None:self.current.append(tuple(self.textarea));self.textarea=None
        elif tag=='option' and self.option is not None:
            if not self.option[3]:self.select[2].append((self.option[0] if self.option[0] is not None else self.option[1],self.option[2]))
            self.option=None
        elif tag=='select' and self.select is not None:
            name,multiple,options=self.select;selected=[v for v,checked in options if checked]
            if not selected and not multiple and options:selected=[options[0][0]]
            self.current.extend((name,v) for v in selected);self.select=None
        elif tag=='form':self.forms.append(self.current);self.current=None


def normalized_plan_form(html,plan_id):
    parser=PlanEditor();parser.feed(html)
    forms=[values for values in parser.forms if dict(values).get('plan_id')==str(plan_id)]
    if len(forms)!=1:raise RuntimeError('exact plan editor was not returned')
    values=forms[0]
    if dict(values).get('lifecycle_status')!='active':raise RuntimeError('normalization only revises active hosting plans')
    changed={'php_versions','php_allowlist','default_php_version','change_reason'}
    return [(k,v) for k,v in values if k not in changed]+[('php_versions','8.5'),('php_allowlist','8.5'),('default_php_version','8.5'),('change_reason','Explicit disposable forward-fixture PHP 8.5 preparation')]


def assert_plan_only_php_changed(before,after):
    def masked(value):
        result=json.loads(json.dumps(value));result.pop('revision',None)
        for path in [('resources','php_allowlist'),('presets','hosting','default_php_version'),('presets','hosting','allowed_php_versions'),('hosting_policy','php','default_version'),('hosting_policy','php','allowed_versions')]:
            node=result
            for key in path[:-1]:node=node.get(key,{})
            node.pop(path[-1],None)
        return result
    if masked(before)!=masked(after):raise RuntimeError('plan revision changed non-PHP contract fields')


def active_php_plans():
    return json.loads(pg("SELECT COALESCE(json_agg(row_to_json(q)),'[]'::json) FROM (SELECT id,revision,php_allowlist,default_php_version,hosting_policy FROM plans WHERE lifecycle_status='active' AND hosting_enabled ORDER BY id) q"))


def plan_needs_php85(plan):
    policy=plan.get('hosting_policy',{}).get('php',{})
    versions=set(v.strip() for v in plan['php_allowlist'].split(',') if v.strip())|set(policy.get('allowed_versions',[]))
    return versions!={'8.5'} or plan['default_php_version']!='8.5' or policy.get('default_version','8.5')!='8.5'


def assert_fixture_entitlements(c,locked_only=False):
    if c.get('target_profile')!='ubuntu-26.04-native':return []
    restriction=" AND s.sync_mode IN ('locked','custom')" if locked_only else ''
    rows=json.loads(pg("SELECT COALESCE(json_agg(row_to_json(q)),'[]'::json) FROM (SELECT e.subscription_id,s.sync_mode,e.php_allowlist,e.default_php_version,e.hosting_policy FROM subscription_entitlements e JOIN subscriptions s ON s.id=e.subscription_id WHERE e.hosting_enabled"+restriction+' ORDER BY e.subscription_id) q'))
    if any(plan_needs_php85(row) for row in rows):raise RuntimeError('native fixture retains incompatible subscription PHP offers; locked/custom snapshots are not rewritten; use a compatible source or Sury target')
    return rows


def normalize_active_plans(c,post):
    plans=[plan for plan in active_php_plans() if plan_needs_php85(plan)]
    if c.get('target_profile')=='ubuntu-26.04-sury' and not c.get('normalize_php85'):
        c['prior_plan_php_intent']=plans
        return []
    if plans and not c.get('normalize_php85'):raise RuntimeError('active plan offers require explicit normalize_php85 fixture preparation')
    c['prior_plan_php_intent']=plans
    for plan in plans:
        identity=str(int(plan['id']));revision=int(plan['revision'])
        history="SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(p) ORDER BY revision),'[]'::jsonb)::text,'UTF8')),'hex') FROM plan_revisions p WHERE plan_id="+identity+' AND revision<='+str(revision)
        before_hash=pg(history)
        before=json.loads(pg('SELECT definition::text FROM plan_revisions WHERE plan_id='+identity+' AND revision='+str(revision)))
        audit="SELECT count(*) FROM audit_events WHERE action='plan.saved' AND target_type='plan' AND target_id="+identity
        old_audit=int(pg(audit))
        values=normalized_plan_form(post.get('service-plans/'+identity),int(identity))
        post('plans',values)
        current=json.loads(pg("SELECT json_build_object('revision',revision,'php_allowlist',php_allowlist,'default_php_version',default_php_version,'hosting_policy',hosting_policy) FROM plans WHERE id="+identity))
        if current['revision']!=revision+1 or plan_needs_php85(current):raise RuntimeError('product plan revision did not commit PHP 8.5 intent')
        after=json.loads(pg('SELECT definition::text FROM plan_revisions WHERE plan_id='+identity+' AND revision='+str(current['revision'])))
        assert_plan_only_php_changed(before,after)
        if pg(history)!=before_hash:raise RuntimeError('immutable prior plan history changed')
        if int(pg(audit))<=old_audit:raise RuntimeError('plan normalization product audit is missing')
        wait("SELECT count(*) FROM subscriptions WHERE plan_id="+identity+" AND sync_mode='synced' AND (sync_status<>'in_sync' OR plan_revision<>"+str(current['revision'])+')','0')
    return plans


def fixture_image(c):
    # A private reviewed spec can pin the image validated by Phase 28. Fallback
    # reads only the exact official nginx namespace from provider-owned state;
    # no mutable tag or unreviewed registry is resolved during preparation.
    image=c.get('oci_image_ref','')
    if not image:
        image=pg("SELECT image_ref FROM application_presets WHERE reseller_id IS NULL AND active AND runtime='oci' AND image_ref ~ '^docker.io/library/nginx@sha256:[a-f0-9]{64}$' ORDER BY id LIMIT 1")
    if not re.fullmatch(r'docker\.io/library/nginx@sha256:[a-f0-9]{64}',image):
        raise RuntimeError('forward fixture requires a reviewed immutable official nginx image; set oci_image_ref from validated Phase 28 evidence or a trusted active catalog')
    return image


def fixture_catalog_slug(c):
    return 'forward-fixture-'+hashlib.sha256(c['run_token'].encode()).hexdigest()[:12]


def source_preflight(c):
    result=roundcube_preflight(c)
    result['oci_image_ref']=fixture_image(c)
    assert_fixture_entitlements(c,locked_only=True)
    if c.get('target_profile','ubuntu-26.04-native')=='ubuntu-26.04-native' and not c.get('normalize_php85') and any(plan_needs_php85(plan) for plan in active_php_plans()):raise RuntimeError('active plan offers require explicit normalize_php85 fixture preparation')
    observed=discover(dict(c))
    result.update({key:observed[key] for key in ('site_id','worker_id','worker_php_version','domain','username','subscription_id')})
    return result


def create_fixture_container(c,post,image):
    image=fixture_image({'oci_image_ref':image})
    c['image_ref']=image;c['catalog_slug']=fixture_catalog_slug(c)
    # Build a dedicated provider recipe through its real product route. Phase28
    # removes its test application, so no retained instance is required here.
    post('application-presets',{'slug':c['catalog_slug'],'name':'Forward migration durable fixture',
        'runtime':'oci','image_ref':image,'active':'true','container_port':80,
        'health_kind':'http','health_path':'/','health_timeout_seconds':30,
        'volumes':json.dumps([{'name':'forward','target':'/forward-data','size_mb':1,'read_only':False}])})
    for suffix in ('home','data','config'):
        command(['install','-d','-m','0700','-o',c['username'],'-g',c['username'],'/var/lib/nakpanel/containers/sub-'+str(c['subscription_id'])+'/'+suffix])
    command(['install','-d','-m','0700','-o',c['username'],'-g',c['username'],'/run/nakpanel-containers/sub-'+str(c['subscription_id'])])
    rootless(c,'pull',image)
    post('subscriptions/'+str(c['subscription_id'])+'/applications',{
        'site_id':c['site_id'],'name':'forward-fixture','runtime':'oci','catalog_slug':c['catalog_slug'],
        'desired_state':'running','route_mode':'prefix','route_prefix':'/forward-fixture/',
        'container_port':80,'health_kind':'http','health_path':'/','health_timeout_seconds':30,
        'secrets':json.dumps({'FORWARD_SECRET':c['application_secret']})})
    c['oci_id']=int(pg("SELECT id FROM application_instances WHERE name='forward-fixture' AND subscription_id="+str(c['subscription_id'])))
    wait("SELECT convergence_status||':'||observed_state FROM application_instances WHERE id="+str(c['oci_id']),'in_sync:healthy')
    return c


def seed(c):
    roundcube_preflight(c)
    image=fixture_image(c)
    c = discover(c)
    post=login(c)
    normalize_active_plans(c,post)
    assert_fixture_entitlements(c)
    wrong = pg("SELECT count(*) FROM (SELECT php_version v FROM sites UNION ALL SELECT desired_php_version FROM sites UNION ALL SELECT php_version FROM php_applications) q WHERE v<>'8.5'")
    if wrong != '0' and (c.get('target_profile','ubuntu-26.04-native')=='ubuntu-26.04-native' or c.get('normalize_php85')):
        if not c.get('normalize_php85'):
            raise RuntimeError('native fixture requires all source PHP intent=8.5; explicit normalize_php85 is only for this disposable fixture setup')
        c['prior_php_intent'] = json.loads(pg("SELECT json_agg(row_to_json(q)) FROM (SELECT id,php_version,desired_php_version FROM sites ORDER BY id) q"))
        pg("BEGIN; UPDATE sites SET php_version='8.5',desired_php_version='8.5'; UPDATE php_applications SET php_version='8.5'; COMMIT;")
        cli('reconcile', '--system')
        wait("SELECT count(*) FROM php_applications WHERE convergence_status<>'in_sync' OR desired_revision<>applied_revision OR php_version<>'8.5'", '0')
    c=discover(c)
    # Fixture setup mirrors the repo's phase28 entitlement preparation. These
    # explicit test-source changes precede the baseline/archive; target restore
    # must retain this resulting intent without further rewriting.
    allowed_slugs=json.loads(pg("SELECT COALESCE(hosting_policy#>'{applications,allowed_catalog_slugs}','[]'::jsonb) FROM subscription_entitlements WHERE subscription_id="+str(c['subscription_id'])))
    if not isinstance(allowed_slugs,list) or any(not isinstance(slug,str) for slug in allowed_slugs):raise RuntimeError('invalid source catalog entitlement')
    allowed_slugs=sorted(set(allowed_slugs+[fixture_catalog_slug(c)]))
    patch = {'permissions': {'mail': True, 'ftps': True, 'sftp': True, 'applications': True, 'custom_oci_images': True,'application_egress':False},
             'mail': {'enabled': True}, 'access': {'ftps_enabled': True},
             'applications': {'catalog_enabled':True,'allowed_catalog_slugs':allowed_slugs,'allowed_runtimes': ['oci'], 'allowed_registries': ['docker.io'], 'rootless': True,'egress_enabled':False},
             'resources': {'max_applications': 3, 'max_ftp_accounts': 4, 'max_sftp_identities': 4, 'max_mailboxes': 4, 'container_storage_mb': 64,'memory_mb':256,'cpu_percent':50,'max_tasks':128}}
    expression = 'hosting_policy'
    for section, fields in patch.items():
        expression = 'jsonb_set(' + expression + ',' + quote('{' + section + '}') + ',(COALESCE(hosting_policy->' + quote(section) + ", '{}'::jsonb)||" + quote(json.dumps(fields)) + '::jsonb),true)'
    pg('UPDATE subscription_entitlements SET max_mailboxes=4,hosting_policy=' + expression + ' WHERE subscription_id=' + str(c['subscription_id']))
    # Dedicated tracked database exercises sealed credentials without changing a
    # WordPress/application database password created by an earlier phase.
    post('databases', {'subscription_id': c['subscription_id'], 'site_id': c['site_id'],
        'engine': 'mariadb', 'db_name': 'np_forward_fixture', 'db_user': 'np_forward_fixture', 'password': c['database_password']})
    wait("SELECT status FROM databases WHERE db_name='np_forward_fixture'", 'active')
    c['database'] = 'np_forward_fixture'
    c['database_user'] = 'np_forward_fixture'
    maria("CREATE TABLE np_forward_canary(id INT PRIMARY KEY,v VARCHAR(160) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci); INSERT INTO np_forward_canary VALUES(1,'" + c['marker'] + "'); CREATE PROCEDURE np_forward_routine() SELECT v FROM np_forward_canary WHERE id=1; CREATE EVENT np_forward_event ON SCHEDULE EVERY 1 DAY STARTS '2030-01-01 00:00:00' DISABLE DO SELECT 1; CREATE TRIGGER np_forward_trigger BEFORE UPDATE ON np_forward_canary FOR EACH ROW SET NEW.v=NEW.v;", c['database'])
    create_fixture_container(c,post,image)
    c['volume_file'] = '/var/lib/nakpanel/containers/sub-{subscription_id}/apps/{oci_id}/volumes/forward/forward-canary'.format(**c)
    Path(c['volume_file']).write_text(c['marker'])
    command(['chown', c['username'] + ':' + c['username'], c['volume_file']])
    c['docroot_file'] = '/home/{username}/domains/{domain}/public_html/forward-canary.txt'.format(**c)
    # Managed public_html may be a release symlink: seed a separate tenant data
    # path for immutable releases, and exercise HTTP through the existing app.
    c['tenant_file'] = '/home/' + c['username'] + '/forward-canary.txt'
    Path(c['tenant_file']).write_text(c['marker'])
    command(['chown', c['username'] + ':' + c['username'], c['tenant_file']])
    post('subscriptions/' + str(c['subscription_id']) + '/sftp', {'name': 'forward-fixture',
        'public_key': c['ssh_public_key'], 'relative_root': 'domains/' + c['domain'] + '/public_html', 'enabled': 'true'})
    post('subscriptions/' + str(c['subscription_id']) + '/ftp', {'site_id': c['site_id'], 'name': 'forwardfixture', 'password': c['ftp_password'], 'enabled': 'true'})
    c['ftp_username'] = 'forwardfixture'
    cli('mail', 'enable', c['domain'])
    c['mailbox'] = 'forwardfixture@' + c['domain']
    cli('mail', 'add', c['mailbox'], '--password', c['mailbox_password'])
    wait("SELECT convergence_status FROM mail_domains WHERE domain=" + quote(c['domain']), 'in_sync')
    wait("SELECT convergence_status FROM ftp_accounts WHERE name='forwardfixture'", 'in_sync')
    client = imaplib.IMAP4_SSL('127.0.0.1', 993, ssl_context=ssl._create_unverified_context(), timeout=30)
    try:
        client.login(c['mailbox'], c['mailbox_password'])
        status, _ = client.append('INBOX', None, None, ('Subject: Forward migration durable canary\r\n\r\n' + c['marker'] + '\r\n').encode())
        if status != 'OK': raise RuntimeError('real IMAP message append failed')
    finally: client.logout()
    pid = command(['systemctl','show','--property=MainPID','--value','nakpanel-php-worker@'+str(c['worker_id'])+'.service'])
    c['worker_secret_sha256'] = worker_secret_digest(pid)
    c['images'] = image_inventory()
    c['oci_digest'] = rootless(c,'image','inspect','--format','{{.Digest}}',c['image_ref'])
    c['oci_image_id'] = rootless(c,'image','inspect','--format','{{.Id}}',c['image_ref'])
    return c


def snapshot(c):
    # Only durable intent participates: observed timestamps/process IDs/jobs are
    # deliberately checked as live behavior below, rather than hashed as data.
    projection = {
        'sites': 'id,domain,username,php_version,desired_php_version,desired_status,https_redirect',
        'plans':'id,reseller_id,name,revision,lifecycle_status,php_allowlist,default_php_version,hosting_policy',
        'plan_revisions':'id,plan_id,revision,lifecycle_status,definition,definition_hash,actor_user_id,actor_label,change_reason',
        'php_applications': 'id,site_id,php_version,hosting_mode,desired_revision',
        'php_workers': 'id,application_id,name,script,processes,desired_state',
        'application_instances': 'id,subscription_id,name,runtime,catalog_slug,catalog_revision,manifest,image_ref,desired_state,desired_revision',
        'application_presets':'id,reseller_id,slug,name,runtime,image_ref,active,manifest_revision,manifest',
        'application_manifest_revisions':'id,preset_id,revision,manifest,image_ref,created_by_user_id',
        'databases': 'id,subscription_id,db_name,db_user',
        'subscription_entitlements': 'subscription_id AS id,hosting_policy',
        'sftp_access_identities': 'id,subscription_id,name,public_key,relative_root,enabled',
        'ftp_accounts': 'id,subscription_id,site_id,name,password_hash,enabled',
        'mail_domains': 'id,subscription_id,domain,enabled,dkim_enabled,dmarc_policy,catch_all',
        'mailboxes': 'id,mail_domain_id,local_part,password_ciphertext,quota_mb,enabled,autoresponder',
        'service_secrets': 'id,secret_id,scope,name,key_version,wrapped_key_nonce,wrapped_data_key,value_nonce,ciphertext',
    }
    intent = {table: pg("SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(q) ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex') FROM (SELECT " + cols + ' FROM ' + table + ') q') for table, cols in projection.items()}
    users = pg('SELECT username FROM subscription_system_accounts ORDER BY username').splitlines()
    identities = [{'name': u, 'uid': int(command(['id', '-u', u])), 'gid': int(command(['id', '-g', u])),
        'subuid': subordinate_row(u,'/etc/subuid'),
        'subgid': subordinate_row(u,'/etc/subgid')} for u in users]
    files = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/etc/nakpanel/secret-keys.json', c['tenant_file'], c['volume_file']]}
    database = c['database']
    result = {
        'intent': intent, 'identities': identities, 'files': files,
        'mariadb': {
            'rows': maria('SELECT id,v FROM np_forward_canary ORDER BY id', database),
            'collation': maria("SELECT COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=" + quote(database) + " AND TABLE_NAME='np_forward_canary' AND COLUMN_NAME='v'"),
            'routine': maria("SELECT ROUTINE_TYPE,ROUTINE_DEFINITION FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=" + quote(database) + " AND ROUTINE_NAME='np_forward_routine'"),
            'event': maria("SELECT STATUS,INTERVAL_VALUE,INTERVAL_FIELD,EVENT_DEFINITION FROM information_schema.EVENTS WHERE EVENT_SCHEMA=" + quote(database) + " AND EVENT_NAME='np_forward_event'"),
            'trigger': maria("SELECT ACTION_TIMING,EVENT_MANIPULATION,ACTION_STATEMENT FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=" + quote(database) + " AND TRIGGER_NAME='np_forward_trigger'")},
        'grants': maria("SELECT PRIVILEGE_TYPE FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA=" + quote(database) + " AND GRANTEE=" + quote("'" + c['database_user'] + "'@'localhost'") + ' ORDER BY PRIVILEGE_TYPE').splitlines(),
    }
    if any(not v for v in result['mariadb'].values()) or not result['grants']:
        raise RuntimeError('incomplete MariaDB fixture (rows/collation/routine/event/trigger/grants)')
    # Read-only SQLite inspection; never run a write transaction on frozen source.
    import sqlite3
    candidates = ['/var/lib/roundcube/roundcube.sqlite', '/var/lib/roundcube/db/roundcube', '/var/lib/dbconfig-common/sqlite3/roundcube/roundcube']
    path = next((p for p in candidates if Path(p).is_file()), None)
    if not path: raise RuntimeError('Roundcube SQLite fixture missing')
    db = sqlite3.connect('file:' + path + '?mode=ro', uri=True)
    try:
        rows = db.execute("SELECT u.preferences,c.name,c.email FROM users u JOIN contacts c USING(user_id) WHERE u.username=? AND c.email='phase29-contact@example.test'", (c['mailbox'],)).fetchall()
        if not rows or 'phase29-roundcube-preference' not in rows[0][0]: raise RuntimeError('Roundcube actual contacts/preferences canary missing')
        result['roundcube'] = hashlib.sha256(json.dumps(rows).encode()).hexdigest()
    finally: db.close()
    return result


def container_limits(c,observed,proc=Path('/proc'),cgroups=Path('/sys/fs/cgroup')):
    pid=observed.get('State',{}).get('Pid',0)
    if not isinstance(pid,int) or pid<=1:raise RuntimeError('actual OCI process is missing')
    uid=re.search(r'(?m)^Uid:\s+([0-9]+)',(proc/str(pid)/'status').read_text())
    if not uid or int(uid[1])!=pwd.getpwnam(c['username']).pw_uid:raise RuntimeError('OCI process lost its exact tenant UID')
    row=next((line.split(':',2)[2] for line in (proc/str(pid)/'cgroup').read_text().splitlines() if line.startswith('0::')),None)
    if not row or not row.startswith('/') or '..' in Path(row).parts:raise RuntimeError('OCI process unified cgroup is missing')
    group=cgroups/row.lstrip('/')
    if (group/'memory.max').read_text().strip()!='268435456':raise RuntimeError('OCI kernel memory limit changed')
    if (group/'pids.max').read_text().strip()!='128':raise RuntimeError('OCI kernel process limit changed')
    values=(group/'cpu.max').read_text().split()
    if len(values)!=2 or not all(v.isdigit() for v in values) or int(values[1])<1 or int(values[0])*100//int(values[1])!=50:raise RuntimeError('OCI kernel CPU limit changed')


def podman_live(c):
    container = pg('SELECT container_name FROM application_generations WHERE application_id=' + str(c['oci_id']) + ' AND desired_revision=(SELECT active_generation FROM application_instances WHERE id=' + str(c['oci_id']) + ')')
    if not container: raise RuntimeError('active OCI generation missing')
    observed = json.loads(rootless(c, 'inspect', container))[0]
    if not observed.get('State', {}).get('Running'): raise RuntimeError('restored OCI container is not running')
    container_limits(c,observed)
    mode=observed.get('HostConfig',{}).get('NetworkMode','')
    if not mode.startswith('slirp4netns') or 'allow_host_loopback=false' not in mode or 'outbound_addr=lo' not in mode:raise RuntimeError('restored OCI network isolation changed')
    endpoint=pg('SELECT endpoint_port FROM application_instances WHERE id='+str(c['oci_id']))
    if not endpoint.isdigit():raise RuntimeError('restored OCI loopback endpoint is missing')
    command(['curl','--fail','--silent','--show-error','--max-time','10','http://127.0.0.1:'+endpoint+'/'])
    listeners=command(['ss','-Hlt','sport = :'+endpoint]).splitlines()
    if not listeners or any('127.0.0.1:'+endpoint not in line for line in listeners):raise RuntimeError('OCI endpoint is not confined to guest loopback')
    digest = rootless(c, 'image', 'inspect', '--format', '{{.Digest}}', c['image_ref'])
    if digest != c['oci_digest']: raise RuntimeError('actual OCI image digest changed')
    if str(observed.get('Image','')).removeprefix('sha256:') != c['oci_image_id'].removeprefix('sha256:'): raise RuntimeError('running container does not use the source immutable image')
    for image in c['images']:
        if rootless(image,'image','inspect','--format','{{.Id}}',image['image_ref']) != image['image_id']: raise RuntimeError('restored OCI image inventory content changed')
    if rootless(c, 'exec', container, 'cat', '/forward-data/forward-canary') != c['marker']: raise RuntimeError('container-mounted persistent volume data missing')
    if rootless(c, 'exec', container, 'cat', '/run/secrets/FORWARD_SECRET') != c['application_secret']: raise RuntimeError('decrypted OCI secret content missing')



def worker_secret_digest(pid):
    prefix = b'PHASE30_SECRET='
    value = next((entry[len(prefix):] for entry in Path('/proc/' + str(pid) + '/environ').read_bytes().split(b'\x00') if entry.startswith(prefix)), b'')
    if not value:
        raise RuntimeError('real PHP worker secret environment is missing')
    return hashlib.sha256(value).hexdigest()


def live(c):
    if maria('CALL np_forward_routine()', c['database'], c['database_user'], c['database_password']) != c['marker']:
        raise RuntimeError('restored tenant DB authentication/routine execution failed')
    pid = command(['systemctl', 'show', '--property=MainPID', '--value', 'nakpanel-php-worker@' + str(c['worker_id']) + '.service'])
    if not pid.isdigit() or int(pid) <= 1: raise RuntimeError('PHP worker did not execute')
    if os.path.realpath('/proc/' + pid + '/exe') != '/usr/bin/php'+c['worker_php_version']: raise RuntimeError('worker executed wrong PHP interpreter')
    if worker_secret_digest(pid) != c['worker_secret_sha256']: raise RuntimeError('restored PHP worker secret environment changed')
    cmdline = Path('/proc/' + pid + '/cmdline').read_bytes()
    script = pg('SELECT script FROM php_workers WHERE id=' + str(c['worker_id']))
    if script.encode() not in cmdline: raise RuntimeError('worker did not execute its desired script')
    podman_live(c)
    if pg("SELECT count(*) FROM php_workers WHERE desired_state='stopped' AND observed_state<>'stopped'") != '0': raise RuntimeError('desired-stopped worker became active')
    if pg("SELECT count(*) FROM php_applications WHERE convergence_status<>'in_sync'") != '0': raise RuntimeError('PHP applications have not converged')
    return {'worker_pid': int(pid), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def tls(c):
    context = ssl.create_default_context(cafile=c['guest_ca'])
    hostname = c['tls_hostname']
    fingerprints = {}
    for port in (443, 7443, 993):
        with socket.create_connection(('127.0.0.1', port), timeout=30) as raw:
            with context.wrap_socket(raw, server_hostname=c['domain'] if port == 443 else hostname) as channel:
                fingerprints[str(port)] = hashlib.sha256(channel.getpeercert(binary_form=True)).hexdigest()
    # FTP_TLS supports explicit control/data TLS. Resolve loopback through a
    # pinned /etc/hosts-free subclass while preserving hostname verification.
    import ftplib
    ftp = ftplib.FTP_TLS(context=context, timeout=30)
    ftp.connect('127.0.0.1', 21)
    ftp.host = hostname
    try:
        ftp.login(c['ftp_username'], c['ftp_password'])
        ftp.prot_p()
        ftp.nlst()
    finally: ftp.close()
    class LoopbackIMAP(imaplib.IMAP4_SSL):
        def _create_socket(self, timeout):
            raw = socket.create_connection(('127.0.0.1', 993), timeout=timeout)
            return self.ssl_context.wrap_socket(raw, server_hostname=hostname)
    client = LoopbackIMAP(hostname, 993, ssl_context=context, timeout=30)
    try:
        client.login(c['mailbox'], c['mailbox_password'])
        if client.select('INBOX')[0] != 'OK': raise RuntimeError('restored mailbox unavailable')
        status, ids = client.search(None, 'SUBJECT', 'Forward migration durable canary')
        if status != 'OK' or not ids[0]: raise RuntimeError('actual mail canary is missing')
        status, payload = client.fetch(ids[0].split()[-1], '(RFC822)')
        if status != 'OK' or not any(isinstance(p, tuple) and c['marker'].encode() in p[1] for p in payload): raise RuntimeError('mail contents changed')
    finally: client.logout()
    # curl pins the destination independently of production DNS and validates CA/SAN.
    body = command(['curl', '--fail', '--silent', '--show-error', '--cacert', c['guest_ca'], '--resolve', c['domain'] + ':443:127.0.0.1', 'https://' + c['domain'] + '/healthz'])
    if body != 'healthy': raise RuntimeError('managed PHP HTTP health fixture failed')
    page = command(['curl', '--fail', '--silent', '--show-error', '--cacert', c['guest_ca'], '--resolve', c['domain'] + ':443:127.0.0.1', 'https://' + c['domain'] + '/'])
    if 'public=visible' not in page or 'secret=present' not in page: raise RuntimeError('managed PHP HTTP environment/secret fixture failed')
    import smtplib
    with smtplib.SMTP('127.0.0.1',587,timeout=30) as smtp:
        smtp.ehlo()
        smtp._host=hostname
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(c['mailbox'],c['mailbox_password'])
    dns = command(['dig', '+short', '@127.0.0.1', c['domain'], 'SOA'])
    if not dns: raise RuntimeError('authoritative DNS answer missing')
    return {'trusted_protocols': ['https', 'panel', 'imaps', 'ftps-data', 'smtp-starttls-auth', 'dns'], 'leaf_sha256': fingerprints}


def frozen():
    if pg('SHOW default_transaction_read_only') != 'on' or maria('SELECT @@global.read_only') != '1': raise RuntimeError('source databases are not frozen read-only')
    for unit in ['nakpanel.service', 'nakpanel-agent.service', 'nginx.service', 'stalwart-mail.service','nakpanel-proftpd.service'] + managed_writers():
        result = subprocess.run(['systemctl', 'is-active', '--quiet', unit])
        if result.returncode == 0: raise RuntimeError('source writer service remains active')
    return {'readonly': True}


def freeze(c, keep_agent=False):
    writers = managed_writers()
    services=['nakpanel.service','nginx.service','stalwart-mail.service','nakpanel-proftpd.service']
    if not keep_agent: services.append('nakpanel-agent.service')
    command(['systemctl', 'stop'] + services + writers)
    pg('ALTER DATABASE nakpanel SET default_transaction_read_only=on')
    maria('SET GLOBAL read_only=ON')
    return {'writers_frozen_for_backup': True} if keep_agent else frozen()


if __name__ == '__main__':
    try:
        request = json.load(sys.stdin)
        action, config = request['action'], request['config']
        handlers = {'source-preflight': source_preflight, 'seed': seed, 'snapshot': snapshot, 'live': live, 'tls': tls, 'freeze': freeze, 'cache-target-images':cache_target_images}
        if action == 'freeze-for-backup': result = freeze(config,keep_agent=True)
        elif action == 'frozen': result = frozen()
        elif action in handlers: result = handlers[action](config)
        else: raise ValueError('unknown guest fixture action')
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        print('forward fixture probe failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
