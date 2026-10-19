import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import hashlib
import json
import os
import tempfile
import ast
import subprocess
import sys
import struct

path = Path(__file__).with_name('ubuntu-forward-migration-fixture.py')
spec = importlib.util.spec_from_file_location('forward_fixture', path)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
probe_spec = importlib.util.spec_from_file_location('forward_probe', path.with_name('ubuntu-forward-migration-probe.py'))
probe = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probe)

class ForwardFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir=tempfile.TemporaryDirectory()
        cls.private=Path(cls.keydir.name)/'private.pem';cls.public=Path(cls.keydir.name)/'public.pem'
        subprocess.run(['openssl','genrsa','-out',str(cls.private),'2048'],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(cls.private),'-pubout','-out',str(cls.public)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):cls.keydir.cleanup()

    def signed_bundle(self,directory,development=False):
        root=Path(directory)/'release';root.mkdir()
        elf=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+b'\0'*9,2,183,1,0,64,0,0,64,56,1,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0,0,120,120,4096)
        files={'VERSION':b'29.0.0\n','go.mod':b'module example\n','go.sum':b'checksums\n','Makefile':b'build:\n','migrations/00001.sql':b'-- migration\n','deploy/install/install.sh':b'#!/bin/sh\nexit 0\n'}
        files.update({'bin/'+name:elf for name in ('panel','agent','panelctl')})
        for name,data in files.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        manifest=dict(schema_version=1,version='29.0.0',commit='a'*40,go_toolchain='go1.26.9',cgo_enabled=False,os='linux',architecture='arm64',cpu_baseline='v8.0',development=development,files={name:hashlib.sha256(data).hexdigest() for name,data in files.items()})
        (root/'manifest.json').write_text(json.dumps(manifest))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.private),'-out',str(root/'manifest.sig'),str(root/'manifest.json')],check=True,capture_output=True)
        return root

    def test_host_staging_authenticates_signature_version_arch_and_development_before_vm_access(self):
        for case in ('tampered','wrong-version','wrong-arch','development','valid'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                bundle=self.signed_bundle(directory,case=='development')
                if case=='tampered':(bundle/'bin/panel').write_bytes(b'tampered')
                version='28.0.0' if case=='wrong-version' else '29.0.0'
                architecture='amd64' if case=='wrong-arch' else 'arm64'
                if case=='valid':
                    staged=Path(fixture.stage_target_bundle(bundle,self.public,version,architecture,'0'))
                    try:
                        self.assertEqual(staged.stat().st_mode&0o777,0o700)
                        (bundle/'bin/panel').write_bytes(b'changed after authentication')
                        self.assertNotEqual((staged/'bundle/bin/panel').read_bytes(),b'changed after authentication')
                    finally:fixture.discard_target_bundle(staged)
                else:
                    with self.assertRaisesRegex(ValueError,'bundle verification'):fixture.stage_target_bundle(bundle,self.public,version,architecture,'0')
                if case=='development':
                    staged=fixture.stage_target_bundle(bundle,self.public,version,architecture,'1');fixture.discard_target_bundle(staged)

    def test_private_spec_requires_owned_source_and_real_inputs(self):
        with self.assertRaises(ValueError): fixture.validate_spec({})
        item = fixture.example_spec()
        item['source_vm'] = 'nakpanel-lab'
        with self.assertRaises(ValueError): fixture.validate_spec(item)

    def php_inventory(self):
        policy={'php':{'default_version':'8.3','allowed_versions':['8.3','8.2']},'resources':{'memory_mb':256}}
        plan={'id':4,'revision':1,'lifecycle_status':'retired','php_allowlist':'8.3,8.2','default_php_version':'8.3','hosting_policy':policy}
        row={'subscription_id':1,'plan_id':4,'sync_mode':'synced','source_revision':1,'disk_mb':-1,'php_allowlist':'8.3,8.2','default_php_version':'8.3','hosting_policy':policy}
        return {'selected':[{'kind':'site','id':1,'php_version':'8.3'}],'plans':[plan],'subscriptions':[row],'addons':[],'overrides':[]}

    def test_override_only_php_offers_are_rejected_without_remediation_or_seed(self):
        for profile,version in [('ubuntu-26.04-native','8.3'),('ubuntu-26.04-native','8.2'),('ubuntu-26.04-sury','8.2')]:
            inventory={'selected':[{'php_version':'8.5'}],'plans':[],'subscriptions':[],'addons':[],
                       'overrides':[{'kind':'subscription','id':1,'hosting_policy':{'php':{'allowed_versions':[version]}}}]}
            with self.subTest(profile=profile,version=version),patch.object(probe,'pg',return_value=json.dumps(inventory)),patch.object(probe,'command') as execute,patch.object(probe,'login') as login:
                with self.assertRaisesRegex(RuntimeError,'override.*'+version):probe.assert_fixture_php_inventory({'target_profile':profile,'normalize_php85':True,'remediate_stale_php82':True},allow_preparation=True)
                execute.assert_not_called();login.assert_not_called()

    def test_null_php_override_fields_inherit_without_hiding_inherited_base_offers(self):
        for patch_value in ({'php':None},{'php':{'allowed_versions':None,'default_version':None}}):
            inventory={'selected':[{'php_version':'8.5'}],'plans':[],'subscriptions':[],'addons':[],
                       'overrides':[{'kind':'site','id':1,'hosting_policy':patch_value}]}
            with self.subTest(patch=patch_value),patch.object(probe,'pg',return_value=json.dumps(inventory)):
                probe.assert_fixture_php_inventory({'target_profile':'ubuntu-26.04-native'})
            inventory['subscriptions']=self.php_inventory()['subscriptions']
            inventory['plans']=self.php_inventory()['plans']
            with patch.object(probe,'pg',return_value=json.dumps(inventory)):
                with self.assertRaisesRegex(RuntimeError,'8.2'):probe.assert_fixture_php_inventory({'target_profile':'ubuntu-26.04-sury'})
        for invalid in ({'php':'invalid'},{'php':{'allowed_versions':'8.5'}},{'php':{'allowed_versions':[None]}},{'php':{'default_version':False}}):
            with self.subTest(invalid=invalid),self.assertRaises(RuntimeError):probe.php_offers({'hosting_policy':invalid})

    def test_partial_preparation_retains_private_before_receipt_and_failure_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            c=fixture.example_spec();c.update(run_token='fixture-test',source_vm='nakpanel-source-fixture-test',remediate_stale_php82=True)
            spec=Path(directory)/'spec.json';fixture.private_write(spec,json.dumps(c));output=Path(directory)/'prepared'
            inventory=self.php_inventory();committed=[]
            def execute(args,**kwargs):
                self.assertEqual(args[0],'ssh-keygen');key=Path(args[-1]);key.write_text('key');Path(str(key)+'.pub').write_text('public')
                return ''
            def check(config,vm,stage):
                if stage=='source-preflight':return {'prior_php_inventory':inventory}
                self.assertEqual(stage,'seed')
                receipt=json.loads((output/'preparation-receipt.json').read_text())
                self.assertEqual(receipt['status'],'running');self.assertEqual(receipt['stage'],'source-php-preparation-and-seed')
                self.assertEqual(receipt['before_php_inventory'],inventory);committed.append('product revision committed')
                raise RuntimeError('later product sync failed')
            with patch.object(fixture,'identity'),patch.object(fixture,'run',side_effect=execute),patch.object(fixture,'probe',side_effect=check):
                with self.assertRaisesRegex(RuntimeError,'later product'):fixture.prepare(spec,output)
            receipt_path=output/'preparation-receipt.json';receipt=json.loads(receipt_path.read_text())
            self.assertEqual(committed,['product revision committed']);self.assertEqual(receipt_path.stat().st_mode&0o777,0o600)
            self.assertEqual(receipt['status'],'failed');self.assertEqual(receipt['stage'],'source-php-preparation-and-seed')
            self.assertIs(receipt['remediate_stale_php82'],True);self.assertNotIn('admin_password',receipt)
            self.assertFalse((output/'fixture.json').exists())

    def test_php82_preflight_rejects_both_profiles_before_login_or_mutation(self):
        inventory=self.php_inventory()
        for profile in ('ubuntu-26.04-native','ubuntu-26.04-sury'):
            with self.subTest(profile=profile),patch.object(probe,'roundcube_preflight',return_value={}),patch.object(probe,'fixture_image',return_value='pinned'),patch.object(probe,'pg',return_value=json.dumps(inventory)),patch.object(probe,'discover') as discover,patch.object(probe,'login') as login,patch.object(probe,'command') as execute:
                with self.assertRaisesRegex(RuntimeError,'8.2.*remediate_stale_php82'):
                    probe.source_preflight({'target_profile':profile,'normalize_php85':True})
                discover.assert_not_called();login.assert_not_called();execute.assert_not_called()

    def test_php82_optin_never_allows_selected_default_locked_custom_or_addon_changes(self):
        for case in ('selected','default','locked','custom','addon'):
            inventory=self.php_inventory()
            if case=='selected':inventory['selected'][0]['php_version']='8.2'
            elif case=='default':inventory['plans'][0]['default_php_version']='8.2'
            elif case in ('locked','custom'):inventory['subscriptions'][0]['sync_mode']=case
            else:inventory['addons']=[{'id':1,'php_allowlist':'8.2','hosting_policy':{}}]
            with self.subTest(case=case),patch.object(probe,'pg',return_value=json.dumps(inventory)),patch.object(probe,'login') as login,patch.object(probe,'command') as execute:
                with self.assertRaises(RuntimeError):probe.assert_fixture_php_inventory({'target_profile':'ubuntu-26.04-sury','remediate_stale_php82':True},allow_preparation=True)
                login.assert_not_called();execute.assert_not_called()

    def test_php82_optin_is_fixture_only_and_post_preparation_inventory_is_strict(self):
        with patch.object(probe,'pg',return_value=json.dumps(self.php_inventory())):
            config={'target_profile':'ubuntu-26.04-sury','remediate_stale_php82':True}
            self.assertEqual(probe.assert_fixture_php_inventory(config,allow_preparation=True)['plans'][0]['id'],4)
            with self.assertRaisesRegex(RuntimeError,'8.2'):probe.assert_fixture_php_inventory(config)
        item=fixture.example_spec();self.assertIs(item.get('remediate_stale_php82'),False)
        item.update(source_vm='nakpanel-source-fixture-test',run_token='fixture-test',remediate_stale_php82='true')
        with self.assertRaisesRegex(ValueError,'boolean'):fixture.validate_spec(item)

    def test_retired_plan_editor_preserves_lifecycle_and_surviving_php_offers(self):
        html='<form action="/plans" method="post"><input name="plan_id" value="4"><input name="name" value="Legacy Unlimited"><input name="lifecycle_status" value="retired"><input name="disk_mb" value="-1"><input name="php_allowlist" value="8.3,8.2,8.4"><input name="default_php_version" value="8.3"></form>'
        values=probe.normalized_plan_form(html,4,versions=['8.3','8.4'],default='8.3',lifecycle='retired')
        self.assertEqual(dict(values)['lifecycle_status'],'retired');self.assertEqual(dict(values)['disk_mb'],'-1')
        self.assertEqual(dict(values)['default_php_version'],'8.3');self.assertEqual(dict(values)['php_allowlist'],'8.3,8.4')
        self.assertEqual([v for k,v in values if k=='php_versions'],['8.3','8.4'])
        with self.assertRaisesRegex(RuntimeError,'lifecycle'):probe.normalized_plan_form(html,4,lifecycle='active')

    def test_referenced_retired_plan_revision_is_audited_and_only_php_changes(self):
        for native in (False,True):
            with self.subTest(native=native):
                plan=self.php_inventory()['plans'][0];old={'revision':1,'name':'Legacy Unlimited','lifecycle_status':'retired','resources':{'disk_mb':-1,'php_allowlist':'8.3,8.2'},'presets':{'hosting':{'default_php_version':'8.3','allowed_php_versions':['8.3','8.2']}},'hosting_policy':plan['hosting_policy']}
                versions=['8.5'] if native else ['8.3'];default=versions[0]
                new=json.loads(json.dumps(old));new['revision']=2;new['resources']['php_allowlist']=','.join(versions);new['presets']['hosting'].update(default_php_version=default,allowed_php_versions=versions);new['hosting_policy']['php'].update(default_version=default,allowed_versions=versions)
                changed=[]
                class API:
                    def get(self,path):
                        if path!='service-plans/4':raise AssertionError('wrong retired plan editor')
                        return '<form action="/plans" method="post"><input name="plan_id" value="4"><input name="lifecycle_status" value="retired"><input name="disk_mb" value="-1"></form>'
                    def __call__(self,path,values):
                        if path!='plans':raise AssertionError('not a product revision')
                        changed.append(dict(values))
                def query(sql):
                    if 'row_to_json(q)' in sql:
                        self.assertIn("sync_mode='synced'",sql);self.assertIn("retired",sql)
                        return json.dumps([plan])
                    if 'jsonb_agg(to_jsonb(p)' in sql:return 'immutable-history'
                    if 'definition::text' in sql:return json.dumps(new if 'revision=2' in sql else old)
                    if 'audit_events' in sql:return str(len(changed))
                    if 'json_build_object' in sql:return json.dumps(dict(plan,revision=2,php_allowlist=','.join(versions),default_php_version=default,hosting_policy=new['hosting_policy']))
                    raise AssertionError('unexpected SQL')
                config={'target_profile':'ubuntu-26.04-native' if native else 'ubuntu-26.04-sury','normalize_php85':native,'remediate_stale_php82':True}
                with patch.object(probe,'pg',side_effect=query),patch.object(probe,'wait'):
                    probe.normalize_active_plans(config,API())
                self.assertEqual(len(changed),1);self.assertEqual(changed[0]['lifecycle_status'],'retired')
                self.assertEqual(changed[0]['php_allowlist'],','.join(versions));self.assertEqual(changed[0]['default_php_version'],default)

    def test_stale_synced_snapshot_uses_product_sync_without_changing_non_php_contract(self):
        initial=self.php_inventory();initial['plans'][0].update(php_allowlist='8.3',hosting_policy={'php':{'default_version':'8.3','allowed_versions':['8.3']}})
        final=json.loads(json.dumps(initial));row=final['subscriptions'][0];row.update(php_allowlist='8.3',source_revision=2);row['hosting_policy']['php']['allowed_versions']=['8.3']
        changed=[]
        def post(route,values):changed.append((route,values))
        def query(sql):
            if 'audit_events' in sql:return str(len(changed))
            raise AssertionError('unexpected raw SQL mutation')
        with patch.object(probe,'fixture_php_inventory',side_effect=[initial,final]),patch.object(probe,'pg',side_effect=query):
            probe.refresh_synced_php_snapshots({'target_profile':'ubuntu-26.04-sury'},post)
        self.assertEqual(changed,[('subscriptions/1/sync',{})])
        bad=json.loads(json.dumps(final));bad['subscriptions'][0]['disk_mb']=10
        with self.assertRaisesRegex(RuntimeError,'non-PHP'):probe.assert_snapshot_only_php_changed(initial['subscriptions'],bad['subscriptions'])

    def test_sury_snapshot_refresh_cannot_drop_other_supported_php_or_change_default(self):
        initial=self.php_inventory()['subscriptions'];initial[0]['php_allowlist']='8.3,8.2,8.4'
        final=json.loads(json.dumps(initial));final[0]['php_allowlist']='8.3'
        with self.assertRaisesRegex(RuntimeError,'remaining PHP'):probe.assert_snapshot_only_php_changed(initial,final,preserve_supported_php=True)
        final=json.loads(json.dumps(initial));final[0]['php_allowlist']='8.3,8.4';final[0]['default_php_version']='8.4'
        with self.assertRaisesRegex(RuntimeError,'default PHP'):probe.assert_snapshot_only_php_changed(initial,final,preserve_supported_php=True)

    def test_optin_cannot_remediate_a_synced_snapshot_without_eligible_source_plan(self):
        inventory=self.php_inventory();inventory['plans']=[]
        with patch.object(probe,'pg',return_value=json.dumps(inventory)):
            with self.assertRaisesRegex(RuntimeError,'source plan'):probe.assert_fixture_php_inventory({'target_profile':'ubuntu-26.04-sury','remediate_stale_php82':True},allow_preparation=True)

    @unittest.skipUnless(os.environ.get('NAKPANEL_FORWARD_PHP_TEST_DSN'),'requires isolated PostgreSQL TEMP-table qualification DSN')
    def test_complete_php_inventory_with_real_postgres(self):
        psql=os.environ.get('NAKPANEL_FORWARD_PHP_TEST_PSQL','psql')
        prefix="""BEGIN;
CREATE TEMP TABLE sites(id bigint,php_version text,desired_php_version text);
CREATE TEMP TABLE php_applications(id bigint,php_version text);
CREATE TEMP TABLE plans(id bigint,revision int,lifecycle_status text,hosting_enabled bool,php_allowlist text,default_php_version text,hosting_policy jsonb);
CREATE TEMP TABLE subscriptions(id bigint,plan_id bigint,sync_mode text);
CREATE TEMP TABLE subscription_entitlements(subscription_id bigint,hosting_enabled bool,php_allowlist text,default_php_version text,hosting_policy jsonb);
CREATE TEMP TABLE addon_plans(id bigint,php_allowlist text,hosting_policy jsonb);
CREATE TEMP TABLE subscription_addons(subscription_id bigint,addon_plan_id bigint);
CREATE TEMP TABLE subscription_policy_overrides(subscription_id bigint,policy_patch jsonb);
CREATE TEMP TABLE site_policy_overrides(site_id bigint,policy_patch jsonb);
INSERT INTO sites VALUES(1,'8.3','8.3');
INSERT INTO php_applications VALUES(1,'8.3');
INSERT INTO plans VALUES(1,2,'active',true,'8.3,8.4,8.5','8.4','{}'),(4,1,'retired',true,'8.3,8.2','8.3','{}'),(5,1,'retired',true,'8.1','8.1','{}'),(6,1,'draft',true,'9.9','9.9','{}');
INSERT INTO subscriptions VALUES(1,4,'synced');
INSERT INTO subscription_entitlements VALUES(1,false,'8.3,8.2','8.3','{"php":{"default_version":"8.3","allowed_versions":["8.3","8.2"]}}');
INSERT INTO subscription_policy_overrides VALUES(1,'{"permissions":{"hosting":true},"php":{"allowed_versions":["8.2"]}}');
INSERT INTO site_policy_overrides VALUES(1,'{"php":{"default_version":"8.4"}}');
"""
        def query(sql):
            result=subprocess.run([psql,os.environ['NAKPANEL_FORWARD_PHP_TEST_DSN'],'-XAtq','-v','ON_ERROR_STOP=1','-c',prefix+sql+';ROLLBACK;'],check=True,capture_output=True,text=True)
            return result.stdout.strip()
        with patch.object(probe,'pg',side_effect=query):
            inventory=probe.fixture_php_inventory()
            self.assertEqual([row['id'] for row in inventory['plans']],[1,4])
            self.assertEqual(len(inventory['selected']),3);self.assertEqual(inventory['subscriptions'][0]['sync_mode'],'synced')
            self.assertIs(inventory['subscriptions'][0]['hosting_enabled'],False)
            self.assertEqual(len(inventory['overrides']),2)
            with self.assertRaisesRegex(RuntimeError,'8.2'):probe.assert_fixture_php_inventory({'target_profile':'ubuntu-26.04-sury'})

    def test_preparation_rejects_unsupported_webmail_before_seed_or_local_state(self):
        with tempfile.TemporaryDirectory() as directory:
            c=fixture.example_spec();c.update(run_token='fixture-test',source_vm='nakpanel-source-fixture-test')
            spec=Path(directory)/'spec.json';fixture.private_write(spec,json.dumps(c))
            output=Path(directory)/'prepared'
            stages=[]
            def check(config,vm,stage):
                stages.append(stage)
                raise RuntimeError('configured non-SQLite webmail')
            with patch.object(fixture,'identity'),patch.object(fixture,'probe',side_effect=check),patch.object(fixture,'run') as execute:
                with self.assertRaisesRegex(RuntimeError,'non-SQLite'): fixture.prepare(spec,output)
                execute.assert_not_called()
            self.assertEqual(stages,['source-preflight'])
            self.assertFalse(output.exists())

    def test_seed_refuses_non_sqlite_before_any_php_or_database_changes(self):
        with patch.object(probe,'roundcube_preflight',side_effect=RuntimeError('configured non-SQLite')),patch.object(probe,'discover') as discover,patch.object(probe,'pg') as pg:
            with self.assertRaisesRegex(RuntimeError,'non-SQLite'):probe.seed({})
            discover.assert_not_called();pg.assert_not_called()

    def test_source_roundcube_preflight_reads_config_without_executing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'debian-db.php'
            config.write_text("<?php\n$dbtype='mysql';\n$dbpass='secret-canary';\nfile_put_contents('/tmp/unsafe','bad');\n")
            with patch.object(probe,'command') as execute:
                with self.assertRaisesRegex(RuntimeError,'configured non-SQLite') as failure:probe.roundcube_preflight({},Path(directory))
                self.assertNotIn('secret-canary',str(failure.exception));execute.assert_not_called()

    def test_fixture_image_requires_reviewed_immutable_official_namespace(self):
        pinned='docker.io/library/nginx@sha256:'+'a'*64
        with patch.object(probe,'pg') as query:
            self.assertEqual(probe.fixture_image({'oci_image_ref':pinned}),pinned);query.assert_not_called()
        for invalid in ('docker.io/library/nginx:alpine','evil.test/library/nginx@sha256:'+'a'*64,''):
            with self.subTest(invalid=invalid),patch.object(probe,'pg',return_value=invalid):
                with self.assertRaisesRegex(RuntimeError,'reviewed immutable'):probe.fixture_image({'oci_image_ref':invalid})
        with patch.object(probe,'pg',return_value=pinned):
            self.assertEqual(probe.fixture_image({}),pinned)

    def test_seed_without_catalog_digest_refuses_before_any_mutation(self):
        with patch.object(probe,'roundcube_preflight'),patch.object(probe,'pg',return_value=''),patch.object(probe,'discover') as discover,patch.object(probe,'command') as execute,patch.object(probe,'login') as login:
            with self.assertRaisesRegex(RuntimeError,'reviewed immutable'):probe.seed({})
            discover.assert_not_called();execute.assert_not_called();login.assert_not_called()

    def test_dedicated_container_uses_provider_catalog_and_real_volume_secret_contract(self):
        c={'run_token':'fixture-test','username':'npfixture','subscription_id':3,'site_id':7,'application_secret':'secret-canary'}
        image='docker.io/library/nginx@sha256:'+'a'*64
        calls=[]
        def post(route,values):calls.append((route,values))
        with patch.object(probe,'command'),patch.object(probe,'rootless') as rootless,patch.object(probe,'pg',return_value='4'),patch.object(probe,'wait'):
            probe.create_fixture_container(c,post,image)
        self.assertEqual(c['image_ref'],image);self.assertEqual(c['oci_id'],4)
        self.assertEqual([row[0] for row in calls],['application-presets','subscriptions/3/applications'])
        recipe,app=calls[0][1],calls[1][1]
        self.assertEqual(recipe['image_ref'],image);self.assertEqual(recipe['slug'],app['catalog_slug'])
        self.assertEqual(json.loads(recipe['volumes']),[{'name':'forward','target':'/forward-data','size_mb':1,'read_only':False}])
        self.assertEqual(recipe['container_port'],80);self.assertEqual(recipe['health_path'],'/')
        self.assertEqual(json.loads(app['secrets']),{'FORWARD_SECRET':'secret-canary'})
        self.assertNotIn('image_ref',app);rootless.assert_called_once_with(c,'pull',image)

    def test_forward_container_limits_check_real_process_cgroup_files(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);proc=root/'proc';group=root/'cgroup';(proc/'42').mkdir(parents=True);(group/'fixture').mkdir(parents=True)
            (proc/'42/status').write_text('Uid:\t10000\t10000\t10000\t10000\n')
            (proc/'42/cgroup').write_text('0::/fixture\n')
            for name,value in {'memory.max':'268435456','pids.max':'128','cpu.max':'50000 100000'}.items():(group/'fixture'/name).write_text(value)
            with patch.object(probe.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=10000)):
                probe.container_limits({'username':'npfixture'},{'State':{'Pid':42}},proc,group)
                (group/'fixture/memory.max').write_text('max')
                with self.assertRaisesRegex(RuntimeError,'memory limit'):probe.container_limits({'username':'npfixture'},{'State':{'Pid':42}},proc,group)

    def test_plan_form_roundtrip_preserves_controls_except_explicit_php_changes(self):
        html="""<form action="/plans" method="post"><input name="plan_id" value="7"><input name="name" value="Custom &amp; preserved"><input type="hidden" name="allow_mail" value="false"><input type="checkbox" name="allow_mail" value="true" checked><input type="checkbox" name="allow_ssh" value="true"><input name="ignored" value="disabled" disabled><select name="lifecycle_status"><option value="draft">Draft</option><option value="active" selected>Active</option></select><select name="default_php_version"><option value="8.4" selected>8.4</option><option value="8.5">8.5</option></select><textarea name="description">Exact custom description &amp; data</textarea><input name="php_versions" value="8.3" type="checkbox" checked><input name="php_versions" value="8.4" type="checkbox" checked><input name="php_allowlist" value="8.3,8.4"><input name="change_reason" value="old"></form>"""
        values=probe.normalized_plan_form(html,7)
        self.assertIn(('name','Custom & preserved'),values);self.assertIn(('description','Exact custom description & data'),values)
        self.assertEqual([v for k,v in values if k=='allow_mail'],['false','true'])
        self.assertNotIn('ignored',dict(values));self.assertNotIn('allow_ssh',dict(values))
        self.assertEqual(dict(values)['lifecycle_status'],'active');self.assertEqual([v for k,v in values if k=='php_versions'],['8.5'])
        self.assertEqual(dict(values)['php_allowlist'],'8.5');self.assertEqual(dict(values)['default_php_version'],'8.5')
        with self.assertRaisesRegex(RuntimeError,'exact plan editor'):probe.normalized_plan_form(html,8)

    def test_plan_normalization_allows_only_php_revision_fields(self):
        before={'revision':3,'name':'Custom','resources':{'disk_mb':123,'php_allowlist':'8.3,8.4'},'presets':{'hosting':{'default_php_version':'8.4','allowed_php_versions':['8.3','8.4']}},'hosting_policy':{'php':{'default_version':'8.4','allowed_versions':['8.3','8.4']}}}
        after=json.loads(json.dumps(before));after['revision']=4;after['resources']['php_allowlist']='8.5';after['presets']['hosting'].update(default_php_version='8.5',allowed_php_versions=['8.5']);after['hosting_policy']['php'].update(default_version='8.5',allowed_versions=['8.5'])
        probe.assert_plan_only_php_changed(before,after)
        after['resources']['disk_mb']=124
        with self.assertRaisesRegex(RuntimeError,'non-PHP'):probe.assert_plan_only_php_changed(before,after)

    def test_active_plan_normalization_requires_optin_before_product_mutation(self):
        plans=[{'id':7,'revision':3,'default_php_version':'8.4','php_allowlist':'8.3,8.4','hosting_policy':{'php':{'default_version':'8.4','allowed_versions':['8.3','8.4']}}}]
        with patch.object(probe,'pg',return_value=json.dumps(plans)):
            class API:
                def __call__(self,*args):raise AssertionError('product mutation without opt-in')
                def get(self,*args):raise AssertionError('product form read without opt-in')
            with self.assertRaisesRegex(RuntimeError,'normalize_php85'):probe.normalize_active_plans({'normalize_php85':False},API())

    def test_plan_normalization_uses_product_revision_and_retains_immutable_history(self):
        before={'revision':3,'name':'Custom','resources':{'disk_mb':123,'php_allowlist':'8.4'},'presets':{'hosting':{'default_php_version':'8.4','allowed_php_versions':['8.4']}},'hosting_policy':{'php':{'default_version':'8.4','allowed_versions':['8.4']}}}
        after=json.loads(json.dumps(before));after['revision']=4;after['resources']['php_allowlist']='8.5';after['presets']['hosting'].update(default_php_version='8.5',allowed_php_versions=['8.5']);after['hosting_policy']['php'].update(default_version='8.5',allowed_versions=['8.5'])
        for failure in ('none','history','audit','contract'):
            with self.subTest(failure=failure):
                changed=[]
                class API:
                    def get(self,path):
                        self.path=path
                        return '<form action="/plans" method="post"><input name="plan_id" value="7"><input name="name" value="Custom"><input name="lifecycle_status" value="active"><input name="php_versions" value="8.4"></form>'
                    def __call__(self,path,values):
                        if path!='plans' or dict(values)['default_php_version']!='8.5':raise AssertionError('wrong product revision request')
                        changed.append(values)
                api=API()
                plan={'id':7,'revision':3,'php_allowlist':'8.4','default_php_version':'8.4','hosting_policy':before['hosting_policy']}
                def query(sql):
                    if 'row_to_json(q)' in sql:return json.dumps([plan])
                    if 'jsonb_agg(to_jsonb(p)' in sql:return 'changed-history' if changed and failure=='history' else 'stable-history'
                    if 'definition::text' in sql:
                        value=before if 'revision=3' in sql else json.loads(json.dumps(after))
                        if changed and failure=='contract' and 'revision=4' in sql:value['resources']['disk_mb']=124
                        return json.dumps(value)
                    if 'audit_events' in sql:return '1' if changed and failure!='audit' else '0'
                    if 'json_build_object' in sql:return json.dumps(dict(plan,revision=4,php_allowlist='8.5',default_php_version='8.5',hosting_policy=after['hosting_policy']))
                    raise AssertionError('unexpected SQL boundary')
                with patch.object(probe,'pg',side_effect=query),patch.object(probe,'wait') as wait:
                    if failure=='none':
                        c={'normalize_php85':True};probe.normalize_active_plans(c,api);self.assertEqual(c['prior_plan_php_intent'],[plan]);wait.assert_called_once()
                    else:
                        with self.assertRaises(RuntimeError):probe.normalize_active_plans({'normalize_php85':True},api)
                        wait.assert_not_called()
                self.assertEqual(api.path,'service-plans/7');self.assertEqual(len(changed),1)

    def test_roundcube_canary_uses_root_staged_common_helper_not_public_source(self):
        c={'source_vm':'nakpanel-source-fixture-test','run_token':'fixture-test','architecture':'arm64','remote_src':'/var/lib/nakpanel-qualification/fixture-test/source','mailbox':'canary@example.test'}
        with patch.object(fixture,'run') as run:
            fixture.seed_roundcube(c)
        args=run.call_args.args[0];env=run.call_args.kwargs['env']
        self.assertIn('run_qualification_roundcube_canary',args[2]);self.assertEqual(args[-2:],[c['source_vm'],c['mailbox']])
        self.assertEqual(env['NAKPANEL_REMOTE_SRC'],c['remote_src']);self.assertEqual(env['NAKPANEL_MULTIPASS_IMAGE'],'24.04')
        self.assertNotIn('www-data',args)

    def test_native_fixture_rejects_locked_custom_php_offers_without_rewriting_them(self):
        rows=[{'subscription_id':9,'sync_mode':'locked','php_allowlist':'8.3,8.4','default_php_version':'8.4','hosting_policy':{'php':{'default_version':'8.4','allowed_versions':['8.3','8.4']}}}]
        with patch.object(probe,'pg',return_value=json.dumps(rows)) as query,patch.object(probe,'command') as execute:
            with self.assertRaisesRegex(RuntimeError,'not rewritten'):probe.assert_fixture_entitlements({'target_profile':'ubuntu-26.04-native'},locked_only=True)
            self.assertTrue(all(call.args[0].startswith('SELECT ') for call in query.call_args_list));execute.assert_not_called()
        with patch.object(probe,'pg') as query:
            probe.assert_fixture_entitlements({'target_profile':'ubuntu-26.04-sury'},locked_only=True);query.assert_not_called()

    def test_sury_fixture_preserves_legacy_plan_php_without_normalization(self):
        plans=[{'id':7,'revision':3,'default_php_version':'8.4','php_allowlist':'8.3,8.4','hosting_policy':{'php':{'default_version':'8.4','allowed_versions':['8.3','8.4']}}}]
        with patch.object(probe,'pg',return_value=json.dumps(plans)):
            class API:
                def __call__(self,*args):raise AssertionError('Surý preservation must not revise plans')
                def get(self,*args):raise AssertionError('Surý preservation must not edit plans')
            c={'target_profile':'ubuntu-26.04-sury','normalize_php85':False}
            self.assertEqual(probe.normalize_active_plans(c,API()),[])
            self.assertEqual(c['prior_plan_php_intent'],plans)

    def test_worker_discovery_records_actual_php_for_sury_preservation(self):
        results=[json.dumps({'domain':'phase30-managed.test','username':'npfixture','subscription_id':3}),'8.4']
        with patch.object(probe,'pg',side_effect=results):
            c=probe.discover({'site_id':7,'worker_id':4})
        self.assertEqual(c['worker_php_version'],'8.4')

    def test_every_durable_contract_must_survive(self):
        original = {'intent': 'a', 'identities': ['1001:1001'], 'files': {'key': 'digest'},
                    'mariadb': {'rows': 'canary', 'collation': 'utf8mb4_unicode_520_ci', 'routine': 'body', 'event': 'DISABLED', 'trigger': 'body'},
                    'grants': ['SELECT', 'EXECUTE'], 'roundcube': 'hash'}
        fixture.compare_snapshots(original, dict(original))
        for field in original:
            changed = dict(original)
            changed[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError): fixture.compare_snapshots(original, changed)

    def test_new_engine_grants_may_add_but_never_remove_source_privileges(self):
        base = {'grants': ['SELECT', 'EXECUTE']}
        fixture.compare_snapshots(base, {'grants': ['SELECT', 'EXECUTE', 'SHOW CREATE ROUTINE']})
        with self.assertRaises(ValueError): fixture.compare_snapshots(base, {'grants': ['SELECT']})

    def test_preflight_refuses_incomplete_contract_before_guest_access(self):
        called = []
        with patch.object(fixture,'run',side_effect=lambda *a, **k: called.append(a)):
            with self.assertRaises(ValueError): fixture.validate_spec({'source_vm': 'nakpanel-bad'})
        self.assertEqual(called, [])

    def prepared(self, directory):
        c = fixture.example_spec()
        c.update(run_token='fixture-test', source_vm='nakpanel-source-fixture-test',
                 baseline={'intent':{'sites':'hash'},'identities':[{'name':'npfixture','uid':1001,'gid':1001,'subuid':'','subgid':''}],'files':{'tenant':'digest'},'mariadb':{'rows':'canary'},'roundcube':'digest','grants': ['SELECT']}, archive_sha256=hashlib.sha256(b'archive').hexdigest())
        c.update(worker_php_version='8.4',oci_digest='sha256:'+'c'*64,oci_image_id='d'*64,site_id=1, worker_id=2, subscription_id=3, oci_id=4, username='npfixture', domain='phase30-managed.test', marker='forward-canary-fixture-test', database='np_forward_fixture', database_user='np_forward_fixture', image_ref='docker.io/library/nginx@sha256:'+'a'*64, guest_ca='/etc/nakpanel/forward-fixture-ca.crt', volume_file='/var/lib/nakpanel/containers/sub-3/apps/4/volumes/forward/forward-canary',tenant_file='/home/npfixture/forward-canary.txt',worker_secret_sha256='b'*64,valkey_image='',ftp_username='forwardfixture',mailbox='forwardfixture@phase30-managed.test',images=[{'subscription_id':3,'username':'npfixture','image_ref':'docker.io/library/nginx@sha256:'+'a'*64}])
        for key, name, data in [('archive_file','source.nkbk',b'archive'), ('backup_key_file','archive.key',b'key'), ('ssh_identity_file','sftp-key',b'private'), ('ca_file','ca.crt',b'public')]:
            p = Path(directory) / name
            p.write_bytes(data)
            p.chmod(0o600)
            c[key] = str(p)
        return c

    def test_prepared_contract_binds_archive_and_private_inputs_before_vm_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            with patch.object(fixture, 'run', side_effect=AssertionError('VM access')):
                fixture.validate_prepared(c)
                Path(c['archive_file']).write_bytes(b'different archive')
                with self.assertRaises(ValueError): fixture.validate_prepared(c)

    def test_every_advertised_assertion_dispatches_real_probe_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            path = Path(directory) / 'fixture.json'
            fixture.private_write(path, json.dumps(c))
            with patch.dict(os.environ, {'NAKPANEL_FORWARD_FIXTURE_JSON': str(path)}), patch.object(fixture, 'identity'), patch.object(fixture, 'probe', side_effect=RuntimeError('actual assertion failed')):
                for stage in ['assert-source-readonly','assert-baseline','assert-migration-data','assert-services','assert-trusted-tls','assert-no-source-writes']:
                    with self.subTest(stage=stage), self.assertRaisesRegex(RuntimeError, 'actual assertion failed'):
                        fixture.driver(stage,'nakpanel-target',c['source_vm'],c['run_token'],directory,directory)

    def test_reboot_stage_requires_new_actual_boot_id(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            fixture.private_write(Path(directory) / 'fixture.json', json.dumps(c))
            fixture.private_write(Path(directory) / 'initial-target-boot-id', 'same-boot')
            with patch.dict(os.environ, {'NAKPANEL_FORWARD_FIXTURE_JSON': str(Path(directory) / 'fixture.json')}), patch.object(fixture, 'identity'), patch.object(fixture, 'probe', return_value={'boot_id':'same-boot'}), patch.object(fixture, 'assert_ssh') as ssh:
                with self.assertRaisesRegex(ValueError, 'did not actually reboot'):
                    fixture.driver('assert-reboot','nakpanel-target',c['source_vm'],c['run_token'],directory,directory)
                ssh.assert_not_called()

    def test_readonly_source_rejects_active_worker_or_timer(self):
        from types import SimpleNamespace
        def status(args):
            return SimpleNamespace(returncode=0 if 'nakpanel-php-worker@7.service' in args else 3)
        with patch.object(probe, 'pg', return_value='on'), patch.object(probe, 'maria', return_value='1'), patch.object(probe, 'command', return_value='nakpanel-php-worker@7.service loaded active running worker'), patch.object(probe.subprocess, 'run', side_effect=status):
            with self.assertRaisesRegex(RuntimeError, 'writer'):
                probe.frozen()

    def test_complete_source_image_inventory_rejects_mutable_reference(self):
        rows = [{'subscription_id':2,'username':'npfixture','image_ref':'docker.io/library/nginx:latest'}]
        with patch.object(probe, 'pg', return_value=json.dumps(rows)):
            with self.assertRaisesRegex(RuntimeError, 'immutable'):
                probe.image_inventory()

    def test_worker_secret_digest_requires_actual_nonempty_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / 'environ'
            environment.write_bytes(b'OTHER=value\x00PHASE30_SECRET=private-canary\x00')
            with patch.object(probe, 'Path', return_value=environment):
                self.assertEqual(probe.worker_secret_digest(42), hashlib.sha256(b'private-canary').hexdigest())
                environment.write_bytes(b'OTHER=value\x00')
                with self.assertRaisesRegex(RuntimeError, 'secret environment'):
                    probe.worker_secret_digest(42)

    def test_embedded_guest_programs_compile_before_any_vm_use(self):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value.lstrip().startswith('import '):
                compile(node.value,str(path),'exec')

    def test_prepared_source_requires_complete_durable_and_runtime_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            for field in ['images','worker_secret_sha256','baseline','domain','oci_id']:
                changed = dict(c)
                changed.pop(field)
                with self.subTest(field=field), self.assertRaises(ValueError): fixture.validate_prepared(changed)

    def test_target_system_identities_preserve_exact_ids_and_subordinate_rows(self):
        from types import SimpleNamespace
        users=[{'name':'npfirst','uid':997,'gid':982,'subuid':'npfirst:165339392:65536','subgid':'npfirst:165339392:65536'},
               {'name':'npsecond','uid':982,'gid':981,'subuid':'','subgid':''}]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'etc').mkdir()
            for name in ('subuid','subgid'):
                (root/'etc'/name).write_text('other:200000:65536\nnpfirst:400000:65536\nnpsecond:500000:65536\n')
            accounts={};groups={};calls=[]
            def execute(args,*a,**kw):
                calls.append(args)
                if args[0]=='groupadd': groups[args[-1]]=int(args[args.index('--gid')+1])
                if args[0]=='useradd':
                    accounts[args[-1]]=SimpleNamespace(pw_name=args[-1],pw_uid=int(args[args.index('--uid')+1]),pw_gid=int(args[args.index('--gid')+1]))
                return ''
            with patch.object(probe,'command',side_effect=execute),patch.object(probe.pwd,'getpwall',return_value=[]),patch.object(probe.grp,'getgrall',return_value=[]),patch.object(probe.pwd,'getpwnam',side_effect=lambda n:accounts[n]):
                probe.install_target_identities({'baseline':{'identities':users}},root)
            self.assertEqual([(accounts[u['name']].pw_uid,accounts[u['name']].pw_gid) for u in users],[(997,982),(982,981)])
            for name in ('subuid','subgid'):
                self.assertEqual((root/'etc'/name).read_text(),'other:200000:65536\nnpfirst:165339392:65536\n')
            for args in calls:
                if args[0]=='useradd':
                    self.assertIn('--system',args)
                    self.assertIn('--no-user-group',args)
                    self.assertEqual(args[args.index('--shell')+1],'/usr/sbin/nologin')

    def test_target_identity_collisions_and_root_reject_before_commands(self):
        from types import SimpleNamespace
        user={'name':'npfirst','uid':997,'gid':982,'subuid':'npfirst:200000:65536','subgid':'npfirst:200000:65536'}
        cases=[([SimpleNamespace(pw_name='other',pw_uid=997,pw_gid=999)],[], 'other:400000:65536\n'),
               ([],[SimpleNamespace(gr_name='other',gr_gid=982)],'other:400000:65536\n'),
               ([],[],'other:200001:65536\n')]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'etc').mkdir()
            for passwd,groups,rows in cases:
                for name in ('subuid','subgid'): (root/'etc'/name).write_text(rows)
                with patch.object(probe,'command') as execute,patch.object(probe.pwd,'getpwall',return_value=passwd),patch.object(probe.grp,'getgrall',return_value=groups):
                    with self.assertRaisesRegex(ValueError,'collision|overlap'):
                        probe.install_target_identities({'baseline':{'identities':[user]}},root)
                    execute.assert_not_called()
            rootuser=dict(user,uid=0)
            with patch.object(probe,'command') as execute:
                with self.assertRaisesRegex(ValueError,'nonroot'):
                    probe.install_target_identities({'baseline':{'identities':[rootuser]}},root)
                execute.assert_not_called()

    def test_native_install_uses_signed_bundle_and_matching_installer_with_private_admin(self):
        program=fixture.target_install_program()
        for fail,allow in ((False,False),(False,True),(True,False),(True,True)):
            with self.subTest(fail=fail,allow_development=allow),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);repo=root/'bundle';repo.mkdir();installer=repo/'deploy/install/install.sh';installer.parent.mkdir(parents=True)
                evidence=root/'observed.json'
                installer.write_text('#!/bin/sh\nexec "'+sys.executable+'" -c '+"'"+"import json,os,sys;from pathlib import Path;a=sys.argv[1:];actual=os.environ.get(\"NAKPANEL_RELEASE_ALLOW_DEVELOPMENT\",\"0\");expected=os.environ[\"INSTALL_EXPECT_ALLOW\"];assert actual==expected;assert (\"--allow-development-bundle\" in a)==(actual==\"1\");assert (Path(a[a.index(\"--bundle\")+1])/\"host-verified\").exists();p=Path(a[a.index(\"--admin-password-file\")+1]);Path(os.environ[\"INSTALL_OBSERVED\"]).write_text(json.dumps({\"args\":a,\"password\":p.read_text(),\"mode\":p.stat().st_mode&0o777,\"path\":str(p)}));sys.exit(int(os.environ[\"INSTALL_FAIL\"]))"+"'"+' "$@"\n')
                import tarfile
                archive=root/'bundle.tar'
                with tarfile.open(archive,'w') as stream:stream.add(repo,arcname='.')
                # The guest preflight verifier must run before even the signed installer.
                verifier="import sys\nfrom pathlib import Path\na=sys.argv[1:];Path(a[a.index('--bundle')+1]+'/host-verified').write_text('verified')\n"
                c={'admin_email':'operator@example.test','admin_password':'private-admin-canary','target_profile':'ubuntu-26.04-native','architecture':'arm64'}
                payload={'config':c,'archive':str(archive),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'public_key':'test-public-key','verifier_program':verifier,'version':'29.0.0','allow_development':allow}
                result=subprocess.run([sys.executable,'-c',program],input=json.dumps(payload),text=True,capture_output=True,env=dict(os.environ,TMPDIR=directory,INSTALL_OBSERVED=str(evidence),INSTALL_FAIL='9' if fail else '0',INSTALL_EXPECT_ALLOW='1' if allow else '0',NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='0' if allow else '1'))
                self.assertEqual(result.returncode!=0,fail,result.stderr)
                observed=json.loads(evidence.read_text())
                self.assertEqual(observed['password'],c['admin_password']);self.assertEqual(observed['mode'],0o600)
                self.assertFalse(Path(observed['path']).exists());self.assertNotIn(c['admin_password'],observed['args'])
                self.assertEqual(observed['args'][observed['args'].index('--admin-email')+1],c['admin_email'])
                self.assertIn('--bundle',observed['args']);self.assertIn('--release-public-key',observed['args']);self.assertEqual('--allow-development-bundle' in observed['args'],allow)
                self.assertNotIn('--bin-dir',observed['args'])

    def test_guest_refuses_correctly_transferred_but_unsigned_payload_before_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=self.signed_bundle(directory)
            (bundle/'bin/panel').write_bytes(b'tampered before transfer')
            import tarfile
            archive=root/'bundle.tar'
            with tarfile.open(archive,'w') as stream:
                for path in sorted(bundle.rglob('*')):
                    if path.is_file():stream.add(path,arcname=path.relative_to(bundle).as_posix(),recursive=False)
            payload={'config':{'architecture':'arm64'},'archive':str(archive),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'public_key':self.public.read_text(),'verifier_program':(fixture.HERE.parent/'release/verify.py').read_text(),'version':'29.0.0','allow_development':False}
            result=subprocess.run([sys.executable,'-c',fixture.target_install_program()],input=json.dumps(payload),text=True,capture_output=True,env=dict(os.environ,TMPDIR=directory))
            self.assertNotEqual(result.returncode,0)
            self.assertIn('SHA256 mismatch',result.stderr)
            self.assertFalse(list(root.glob('nakpanel-forward-install-*')))

    def test_native_install_refuses_changed_archive_before_installer_or_password_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=root/'bad.tar';archive.write_bytes(b'changed')
            payload={'config':{'admin_password':'secret'},'archive':str(archive),'archive_sha256':'0'*64}
            result=subprocess.run([sys.executable,'-c',fixture.target_install_program()],input=json.dumps(payload),text=True,capture_output=True,env=dict(os.environ,TMPDIR=directory))
            self.assertNotEqual(result.returncode,0);self.assertIn('archive digest mismatch',result.stderr)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['bad.tar'])

if __name__ == '__main__': unittest.main()
