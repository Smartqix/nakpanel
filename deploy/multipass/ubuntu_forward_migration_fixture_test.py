import importlib.util
import contextlib
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

    def test_same_shape_migrated_plan_comparison_preserves_every_non_php_field(self):
        before={'plan':{'id':1,'revision':2,'php_allowlist':'8.3,8.4,8.5','default_php_version':'8.4','disk_mb':10,'hosting_policy':{'schema_version':1,'php':{'default_version':'8.4','allowed_versions':['8.3','8.4','8.5']},'unknown':{'keep':True}}},'presets':{'schema_version':1,'php':{'default_version':'8.4','allowed_versions':'8.3,8.4,8.5','memory_limit_mb':128},'hosting':{'web_server':'nginx'}}}
        after=json.loads(json.dumps(before));after['plan'].update(revision=3,php_allowlist='8.5',default_php_version='8.5');after['plan']['hosting_policy']['php'].update(default_version='8.5',allowed_versions=['8.5']);after['presets']['php'].update(default_version='8.5',allowed_versions='8.5')
        probe.assert_plan_only_php_changed(before,after)
        for path,value in [(('plan','disk_mb'),11),(('plan','hosting_policy','unknown','keep'),False),(('presets','php','memory_limit_mb'),256),(('plan','hosting_policy','schema_version'),5)]:
            changed=json.loads(json.dumps(after));node=changed
            for part in path[:-1]:node=node[part]
            node[path[-1]]=value
            with self.subTest(path=path),self.assertRaisesRegex(RuntimeError,'non-PHP'):probe.assert_plan_only_php_changed(before,changed)

    def test_site_php_preparation_uses_product_api_and_preserves_lifecycle_and_redirect(self):
        rows=[{'id':1,'php_version':'8.3','desired_php_version':'8.3','desired_status':'suspended','desired_https_redirect':False}, {'id':2,'php_version':'8.4','desired_php_version':'8.5','desired_status':'active','desired_https_redirect':True}]
        calls=[]
        def query(sql):
            if sql.startswith('SELECT'):
                value=json.loads(json.dumps(rows))
                if calls:
                    for row in value:row.update(php_version='8.5',desired_php_version='8.5')
                return json.dumps(value)
            raise AssertionError('fixture must not mutate SQL')
        with patch.object(probe,'pg',side_effect=query),patch.object(probe,'wait') as wait:
            probe.normalize_site_php({'normalize_php85':True},lambda route,data:calls.append((route,data)))
        self.assertEqual([x[0] for x in calls],['sites/1/hosting','sites/2/hosting'])
        self.assertEqual(calls[0][1],{'desired_status':'suspended','desired_php_version':'8.5','desired_https_redirect':'false'})
        self.assertEqual(calls[1][1]['desired_https_redirect'],'true');self.assertEqual(wait.call_count,3)
        for status in ('pending','failed','deleting'):
            bad=json.loads(json.dumps(rows));bad[1]['desired_status']=status
            with self.subTest(status=status),patch.object(probe,'pg',return_value=json.dumps(bad)):
                with self.assertRaisesRegex(RuntimeError,'lifecycle'):probe.normalize_site_php({'normalize_php85':True},lambda *args:self.fail('mutated before complete validation'))
        with patch.object(probe,'pg',return_value=json.dumps(rows)):
            with self.assertRaisesRegex(RuntimeError,'API failure'):probe.normalize_site_php({'normalize_php85':True},lambda *args:(_ for _ in ()).throw(RuntimeError('API failure')))

    def managed_php_state(self,site_version='8.3',app_version='8.3'):
        app={'id':11,'site_id':1,'subscription_id':7,'hosting_mode':'managed','php_version':app_version,'repository_id':12,'repository_ref':'release/stable','framework_profile':'custom','public_path':'www','health_path':'/ready','shared_paths':['storage','cache'],'composer_install':True,'composer_allow_scripts':False,'composer_allow_plugins':True,'release_retention':7,'desired_state':'active','active_deployment_id':23,'previous_deployment_id':22,'desired_revision':5,'applied_revision':5,'convergence_status':'in_sync'}
        return [{'id':1,'php_version':site_version,'desired_php_version':site_version,'desired_status':'active','desired_https_redirect':True,'application':app,'subscription_status':'active','customer_status':'active','provider_active':True,'pending_deployments':0,'related_intent':'a'*64}]

    def test_managed_php_and_application_only_mismatch_use_full_configuration_api(self):
        for site_version,app_version in [('8.3','8.3'),('8.5','8.4')]:
            rows=self.managed_php_state(site_version,app_version);saved=json.loads(json.dumps(rows));saved[0].update(php_version='8.5',desired_php_version='8.5');saved[0]['application'].update(php_version='8.5',desired_revision=6,applied_revision=6)
            calls=[]
            with self.subTest(site=site_version,app=app_version),patch.object(probe,'pg',return_value=json.dumps(rows)),patch.object(probe,'wait'):
                # Current v1 misses the application-only case and never calls the
                # application API. Model only readonly before/after observations.
                if hasattr(probe,'php_normalization_state'):
                    with patch.object(probe,'php_normalization_state',side_effect=[rows,saved]):probe.normalize_site_php({'normalize_php85':True},lambda route,data:calls.append((route,data)))
                else:probe.normalize_site_php({'normalize_php85':True},lambda route,data:calls.append((route,data)))
            app_calls=[data for route,data in calls if route=='sites/1/php-application']
            self.assertEqual(len(app_calls),1)
            data=app_calls[0];self.assertEqual(data['php_version'],'8.5');self.assertEqual(data['hosting_mode'],'managed');self.assertEqual(data['repository_id'],12);self.assertEqual(data['repository_ref'],'release/stable');self.assertEqual(data['shared_path'],['storage','cache']);self.assertEqual(data['release_retention'],7);self.assertEqual(data['composer_allow_plugins'],'true')
            self.assertEqual([route for route,_ in calls],(['sites/1/hosting'] if site_version!='8.5' else [])+['sites/1/php-application'])

    def test_application_only_php_mismatch_is_not_skipped(self):
        rows=self.managed_php_state('8.5','8.3');saved=json.loads(json.dumps(rows));saved[0]['application'].update(php_version='8.5',desired_revision=6,applied_revision=6);calls=[]
        with patch.object(probe,'pg',return_value=json.dumps(rows)),patch.object(probe,'wait'):
            if hasattr(probe,'php_normalization_state'):
                with patch.object(probe,'php_normalization_state',side_effect=[rows,saved]):probe.normalize_site_php({'normalize_php85':True},lambda *args:calls.append(args))
            else:probe.normalize_site_php({'normalize_php85':True},lambda *args:calls.append(args))
        self.assertEqual([route for route,_ in calls],['sites/1/php-application'])

    def test_managed_php_prevalidates_every_row_and_rejects_non_php_postcondition_drift(self):
        for change in ('suspended','pending-deploy','classic-nondefault','invalid-shared','inactive-provider'):
            rows=self.managed_php_state();bad=json.loads(json.dumps(rows[0]));bad['id']=2;bad['application']['site_id']=2
            if change=='suspended':bad['desired_status']='suspended'
            elif change=='pending-deploy':bad['pending_deployments']=1
            elif change=='classic-nondefault':bad['application']['hosting_mode']='classic'
            elif change=='invalid-shared':bad['application']['shared_paths']='storage'
            else:bad['provider_active']=False
            rows.append(bad)
            with self.subTest(change=change),patch.object(probe,'php_normalization_state',return_value=rows),patch.object(probe,'wait'):
                with self.assertRaises(RuntimeError):probe.normalize_site_php({'normalize_php85':True},lambda *args:self.fail('mutation before complete validation'))
        for key in ('repository_ref','active_deployment_id','desired_state','hosting_mode','related_intent'):
            rows=self.managed_php_state();saved=json.loads(json.dumps(rows));saved[0].update(php_version='8.5',desired_php_version='8.5');saved[0]['application'].update(php_version='8.5',desired_revision=6,applied_revision=6);
            if key=='related_intent':saved[0][key]='b'*64
            else:saved[0]['application'][key]='changed'
            with self.subTest(key=key),patch.object(probe,'php_normalization_state',side_effect=[rows,saved]),patch.object(probe,'wait'):
                with self.assertRaisesRegex(RuntimeError,'non-PHP'):probe.normalize_site_php({'normalize_php85':True},lambda *args:None)

    def test_fixture_capability_api_preserves_base_entitlements_and_existing_override_php(self):
        before={'php':{'allowed_versions':['8.3','8.4','8.5'],'default_version':'8.4'},'web':{'index_files':'index.php'},'permissions':{'ssh':False},'applications':{'allowed_catalog_slugs':['existing-app']}}
        calls=[]
        with patch.object(probe,'pg',side_effect=lambda sql:'a'*64 if 'sha256' in sql else json.dumps(json.loads(calls[-1][1]['policy_patch']) if calls else before)),patch.object(probe,'wait'):
            probe.prepare_fixture_capabilities({'subscription_id':7},lambda route,data:calls.append((route,data)),['forward-test'])
        self.assertEqual(calls[0][0],'subscriptions/7/policy')
        saved=json.loads(calls[0][1]['policy_patch']);self.assertEqual(saved['php'],before['php']);self.assertEqual(saved['web'],before['web']);self.assertIs(saved['permissions']['ssh'],False)
        self.assertIs(saved['permissions']['mail'],True);self.assertEqual(saved['resources']['max_mailboxes'],4)
        self.assertEqual(saved['applications']['allowed_catalog_slugs'],['existing-app','forward-test'])
        self.assertEqual(before['permissions'],{'ssh':False})

    def test_capability_api_never_rewrites_base_and_rejects_malformed_or_failed_api(self):
        for value in ({'resources':'bad'},{'applications':{'allowed_catalog_slugs':'bad'}},[]):
            with self.subTest(value=value),patch.object(probe,'pg',side_effect=lambda sql:'a'*64 if 'sha256' in sql else json.dumps(value)):
                with self.assertRaises(RuntimeError):probe.prepare_fixture_capabilities({'subscription_id':7},lambda *args:self.fail('write before override validation'),['forward-test'])
        calls=[]
        def query(sql):
            if 'sha256' in sql:return ('b' if calls else 'a')*64
            return json.dumps(json.loads(calls[-1][1]['policy_patch']) if calls else {})
        with patch.object(probe,'pg',side_effect=query),patch.object(probe,'wait') as wait:
            with self.assertRaisesRegex(RuntimeError,'immutable base'):probe.prepare_fixture_capabilities({'subscription_id':7},lambda *args:calls.append(args),['forward-test'])
            wait.assert_not_called()
        with patch.object(probe,'pg',side_effect=lambda sql:'a'*64 if 'sha256' in sql else '{}'):
            with self.assertRaisesRegex(RuntimeError,'API failed'):probe.prepare_fixture_capabilities({'subscription_id':7},lambda *args:(_ for _ in ()).throw(RuntimeError('API failed')),['forward-test'])

    def test_durable_projection_hashes_complete_plan_addon_and_subscription_contracts(self):
        projections=probe.intent_projections()
        for table in ('plans','addon_plans','subscriptions','subscription_entitlements','php_applications','php_workers','php_environment_bindings','php_deployments'):
            self.assertIn('to_jsonb',projections[table]);self.assertNotIn('hosting_policy AS',projections[table])
        self.assertIn('subscription_addons',projections)
        self.assertNotIn("- 'plan_id'",projections['subscriptions']);self.assertNotIn("- 'sync_mode'",projections['subscriptions'])
        self.assertNotIn("- 'php_allowlist'",projections['subscription_entitlements'])

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
                    def get(self,path):raise AssertionError('PHP-only operation must not read the full plan editor')
                    def __call__(self,path,values):
                        if path=='plans/4/php-versions/preview':return json.dumps({'ok':True,'plan_id':4,'revision':1,'no_change':False,'preview':{'allowed':True,'changes':[]}}).encode()
                        if path!='plans/4/php-versions':raise AssertionError('not a PHP-only product revision')
                        changed.append(dict(values))
                        return json.dumps({'ok':True,'plan_id':4,'revision':2,'changed':True,'sync_state':'pending'}).encode()
                def query(sql):
                    if 'row_to_json(q)' in sql:
                        self.assertIn("sync_mode='synced'",sql);self.assertIn("retired",sql)
                        return json.dumps([plan])
                    if 'jsonb_agg(to_jsonb(p)' in sql:return 'immutable-history'
                    if 'jsonb_build_object' in sql:
                        value=json.loads(json.dumps(new if changed else old));presets=value.pop('presets');value['id']=4
                        return json.dumps({'plan':value,'presets':presets})
                    if 'audit_events' in sql:return str(len(changed))
                    if 'json_build_object' in sql:return json.dumps(dict(plan,revision=2,php_allowlist=','.join(versions),default_php_version=default,hosting_policy=new['hosting_policy']))
                    raise AssertionError('unexpected SQL')
                config={'target_profile':'ubuntu-26.04-native' if native else 'ubuntu-26.04-sury','normalize_php85':native,'remediate_stale_php82':True}
                with patch.object(probe,'pg',side_effect=query),patch.object(probe,'wait'):
                    probe.normalize_active_plans(config,API())
                self.assertEqual(len(changed),1);self.assertEqual(set(changed[0]),{'expected_revision','php_versions','default_php_version','change_reason'})
                self.assertEqual(changed[0]['expected_revision'],'1');self.assertEqual(changed[0]['default_php_version'],default)

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

    def test_existing_legacy_snapshot_php_mirrors_are_php_leaves_only(self):
        before=self.php_inventory()['subscriptions']
        before[0]['service_presets']={'php':{'allowed_versions':'8.3,8.2','default_version':'8.3','memory_limit_mb':128,'future':{'keep':[None,True]}}}
        after=json.loads(json.dumps(before));after[0].update(php_allowlist='8.5',default_php_version='8.5',source_revision=2)
        after[0]['hosting_policy']['php'].update(default_version='8.5',allowed_versions=['8.5'])
        after[0]['service_presets']['php'].update(allowed_versions='8.5',default_version='8.5')
        probe.assert_snapshot_only_php_changed(before,after)
        for mutation in ('memory','unknown','identity'):
            bad=json.loads(json.dumps(after))
            if mutation=='memory':bad[0]['service_presets']['php']['memory_limit_mb']=129
            elif mutation=='unknown':bad[0]['service_presets']['php']['future']['keep']=[None,False]
            else:bad[0]['plan_id']=999
            with self.subTest(mutation=mutation),self.assertRaisesRegex(RuntimeError,'non-PHP'):probe.assert_snapshot_only_php_changed(before,bad)

    def test_legacy_snapshot_php_mirror_presence_null_and_types_are_preserved(self):
        for presets in ({},{'php':None},{'php':{}},{'php':{'allowed_versions':None,'default_version':None}},{'php':{'allowed_versions':'8.3','default_version':'8.3'}}):
            before=[{'subscription_id':1,'service_presets':presets}]
            probe.assert_snapshot_only_php_changed(before,json.loads(json.dumps(before)),preserve_supported_php=True)
            for replacement in ({'php':{'allowed_versions':['8.3'],'default_version':'8.3'}},{'php':{'allowed_versions':'8.3'}},{'php':{}},{'php':None},{}):
                after=[{'subscription_id':1,'service_presets':replacement}]
                if replacement==presets:continue
                with self.subTest(before=presets,after=replacement),self.assertRaises(RuntimeError):probe.assert_snapshot_only_php_changed(before,after)

    def test_sury_preserves_legacy_snapshot_default_and_all_surviving_csv_offers(self):
        before=self.php_inventory()['subscriptions']
        before[0]['php_allowlist']='8.3,8.4,8.2';before[0]['hosting_policy']['php']['allowed_versions']=['8.3','8.4','8.2']
        before[0]['service_presets']={'php':{'allowed_versions':'8.3,8.4,8.2','default_version':'8.3','memory_limit_mb':128}}
        after=json.loads(json.dumps(before));after[0]['php_allowlist']='8.3,8.4';after[0]['hosting_policy']['php']['allowed_versions']=['8.3','8.4'];after[0]['service_presets']['php']['allowed_versions']='8.4,8.3'
        probe.assert_snapshot_only_php_changed(before,after,preserve_supported_php=True)
        for key,value in (('default_version','8.4'),('allowed_versions','8.3'),('allowed_versions','8.3,8.4,8.5')):
            bad=json.loads(json.dumps(after));bad[0]['service_presets']['php'][key]=value
            with self.subTest(key=key,value=value),self.assertRaisesRegex(RuntimeError,'Surý'):probe.assert_snapshot_only_php_changed(before,bad,preserve_supported_php=True)

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
CREATE TEMP TABLE addon_plans(id bigint,is_active bool,php_allowlist text,hosting_policy jsonb);
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
INSERT INTO addon_plans VALUES(1,true,'8.2','{}'),(2,true,'8.5','{}'),(3,false,'8.1','{}');
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
            self.assertEqual([row['id'] for row in inventory['addons']],[1,2])
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
                    def get(self,path):raise AssertionError('PHP-only operation must not read the full plan editor')
                    def __call__(self,path,values):
                        if path=='plans/7/php-versions/preview':return json.dumps({'ok':True,'plan_id':7,'revision':3,'no_change':False,'preview':{'allowed':True,'changes':[]}}).encode()
                        if path!='plans/7/php-versions' or dict(values)['default_php_version']!='8.5':raise AssertionError('wrong PHP-only product revision request')
                        changed.append(values)
                        return json.dumps({'ok':True,'plan_id':7,'revision':4,'changed':True,'sync_state':'in_sync'}).encode()
                api=API()
                plan={'id':7,'revision':3,'php_allowlist':'8.4','default_php_version':'8.4','hosting_policy':before['hosting_policy']}
                def query(sql):
                    if 'row_to_json(q)' in sql:return json.dumps([plan])
                    if 'jsonb_agg(to_jsonb(p)' in sql:return 'changed-history' if changed and failure=='history' else 'stable-history'
                    if 'jsonb_build_object' in sql:
                        value=json.loads(json.dumps(after if changed else before))
                        if changed and failure=='contract':value['resources']['disk_mb']=124
                        presets=value.pop('presets');value['id']=7
                        return json.dumps({'plan':value,'presets':presets})
                    if 'audit_events' in sql:return '1' if changed and failure!='audit' else '0'
                    if 'json_build_object' in sql:return json.dumps(dict(plan,revision=4,php_allowlist='8.5',default_php_version='8.5',hosting_policy=after['hosting_policy']))
                    raise AssertionError('unexpected SQL boundary')
                with patch.object(probe,'pg',side_effect=query),patch.object(probe,'wait') as wait:
                    if failure=='none':
                        c={'normalize_php85':True};probe.normalize_active_plans(c,api);self.assertEqual(c['prior_plan_php_intent'],[plan]);wait.assert_called_once()
                    else:
                        with self.assertRaises(RuntimeError):probe.normalize_active_plans({'normalize_php85':True},api)
                        wait.assert_not_called()
                self.assertEqual(len(changed),1)

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

    def test_product_preview_rejects_semantic_non_php_drift_before_plan_write(self):
        for value in ({'ok':True,'preview':{'allowed':False}}, {'ok':True,'preview':{'allowed':True,'changes':[{'path':'permissions.mail'}]}}, {'ok':False}, {'ok':True,'preview':{'allowed':True,'changes':'invalid'}}):
            with self.subTest(value=value),self.assertRaisesRegex(RuntimeError,'preview'):probe.assert_php_only_preview(json.dumps(value))
        probe.assert_php_only_preview(json.dumps({'ok':True,'preview':{'allowed':True,'changes':[{'path':'php.default_version'},{'path':'php.allowed_versions'}]}}))
        self.assertNotEqual(probe.plan_form_contract([('disk_mb','1'),('php_versions','8.3')]),probe.plan_form_contract([('disk_mb','2'),('php_versions','8.5')]))

    def test_php_only_plan_form_has_no_full_editor_or_lifecycle_fields(self):
        values=probe.plan_php_form(7,['8.4','8.3'],'8.4')
        self.assertEqual([value for key,value in values if key=='php_versions'],['8.3','8.4'])
        self.assertEqual(dict(values)['expected_revision'],'7')
        self.assertEqual(dict(values)['default_php_version'],'8.4')
        self.assertEqual(set(dict(values)),{'expected_revision','php_versions','default_php_version','change_reason'})
        self.assertIn('qualification',dict(values)['change_reason'])

    def test_php_only_preview_requires_exact_identity_revision_readiness_and_changed_intent(self):
        good={'ok':True,'plan_id':7,'revision':3,'no_change':False,'preview':{'allowed':True,'changes':[{'path':'php.allowed_versions'}]}}
        probe.assert_php_only_preview(json.dumps(good),7,3)
        for patch_value in ({'plan_id':8},{'plan_id':True},{'revision':2},{'revision':True},{'no_change':True},{'no_change':None},{'blockers':[{'code':'php_version_unready'}]},{'ok':False},{'preview':{'allowed':False}},{'preview':{'allowed':True,'changes':[{'path':'permissions.mail'}]}}):
            with self.subTest(patch=patch_value),self.assertRaisesRegex(RuntimeError,'preview'):
                probe.assert_php_only_preview(json.dumps(dict(good,**patch_value)),7,3)
        for bad in ('null','[]','not-json'):
            with self.subTest(raw=bad),self.assertRaises(RuntimeError):probe.assert_php_only_preview(bad,7,3)

    def test_php_only_commit_requires_exact_changed_revision_and_sync_state(self):
        good={'ok':True,'plan_id':7,'revision':4,'changed':True,'sync_state':'pending'}
        for state in ('pending','in_sync'):probe.assert_plan_php_result(json.dumps(dict(good,sync_state=state)),7,4)
        for patch_value in ({'plan_id':8},{'plan_id':True},{'revision':3},{'revision':True},{'changed':False},{'changed':1},{'sync_state':'failed'},{'ok':False}):
            with self.subTest(patch=patch_value),self.assertRaises(RuntimeError):probe.assert_plan_php_result(json.dumps(dict(good,**patch_value)),7,4)

    def test_php_only_preview_rejection_never_posts_commit(self):
        plan={'id':7,'revision':3,'php_allowlist':'8.4','default_php_version':'8.4','hosting_policy':{'php':{'default_version':'8.4','allowed_versions':['8.4']}}}
        for outcome in ('stale','unready','no-op'):
            calls=[]
            def api(route,values):
                calls.append((route,values))
                if route!='plans/7/php-versions/preview':raise AssertionError('commit after preview refusal')
                if outcome=='stale':raise RuntimeError('HTTP 409 stale_revision')
                return json.dumps({'ok':True,'plan_id':7,'revision':3,'no_change':outcome=='no-op','preview':{'allowed':outcome!='unready'},'blockers':[{'code':'php_version_unready'}] if outcome=='unready' else []})
            with self.subTest(outcome=outcome),patch.object(probe,'active_php_plans',return_value=[plan]),patch.object(probe,'plan_contract',return_value={'plan':plan,'presets':{}}),patch.object(probe,'pg',return_value='0'),patch.object(probe,'wait') as wait:
                with self.assertRaises(RuntimeError):probe.normalize_active_plans({'normalize_php85':True},api)
                wait.assert_not_called()
            self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],'plans/7/php-versions/preview')

    def test_non_php_product_preview_stops_before_first_plan_revision(self):
        plan={'id':1,'revision':2,'lifecycle_status':'active','php_allowlist':'8.3,8.4','default_php_version':'8.4','hosting_policy':{'php':{'default_version':'8.4','allowed_versions':['8.3','8.4']}}}
        calls=[]
        class API:
            def get(self,path):raise AssertionError('PHP-only operation must not read the full plan editor')
            def __call__(self,route,values):
                calls.append(route)
                if route!='plans/1/php-versions/preview':raise AssertionError('mutated after failed preview')
                return json.dumps({'ok':True,'plan_id':1,'revision':2,'no_change':False,'preview':{'allowed':True,'changes':[{'path':'dns.default_ttl'}]}})
        with patch.object(probe,'active_php_plans',return_value=[plan]),patch.object(probe,'plan_contract',return_value={'plan':plan,'presets':{}}),patch.object(probe,'pg',return_value='0'),patch.object(probe,'wait') as wait:
            with self.assertRaisesRegex(RuntimeError,'non-PHP'):probe.normalize_active_plans({'normalize_php85':True},API())
            wait.assert_not_called()
        self.assertEqual(calls,['plans/1/php-versions/preview'])

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

class RoundcubePreflightTests(unittest.TestCase):
    # Exact Debian package wrapper already pinned by roundcube-dr-canary.php.
    DEBIAN_WRAPPER = '''<?php
require("/etc/roundcube/debian-db.php");

switch ($dbtype) {
 case "sqlite":
 case "sqlite3":
   $config['db_dsnw'] = "sqlite:///$basepath/$dbname?mode=0640";
   break;
 default:
   if ($dbport != '') $dbport=":$dbport";
   if ($dbserver == '') $dbserver="localhost";
   $config['db_dsnw'] = "$dbtype://$dbuser:$dbpass@$dbserver$dbport/$dbname";
   break;
 }
?>
'''

    def sqlite_config(self, kind='sqlite3', base='/var/lib/dbconfig-common/sqlite3/roundcube', name='roundcube'):
        return "<?php\n$dbtype='"+kind+"';\n$basepath='"+base+"';\n$dbname='"+name+"';\n"

    def inspect_roundcube(self, files, error=None, regular=True, symlink=False, integrity=True):
        from pathlib import PurePosixPath
        from unittest.mock import MagicMock
        contents={'/synthetic/roundcube/'+name:value for name,value in files.items()}
        reads=[];database_checks=[]
        class MockPath(PurePosixPath):
            def exists(self):return str(self) in contents
            def read_text(self):reads.append(str(self));return contents[str(self)]
            def is_file(self):database_checks.append(('regular',str(self)));return regular
            def is_symlink(self):database_checks.append(('symlink',str(self)));return symlink
        connection=MagicMock()
        connection.execute.return_value.fetchall.return_value=[('ok',)] if integrity else [('synthetic-invalid',)]
        with patch.object(probe,'Path',MockPath),patch.object(probe.sqlite3,'connect') as connect,patch.object(probe,'command') as command,patch.object(probe,'pg') as pg,patch.object(probe,'maria') as maria,patch.object(probe.subprocess,'run') as transport:
            connect.return_value.__enter__.return_value=connection
            if error:
                with self.assertRaisesRegex(RuntimeError,error) as failure:
                    probe.roundcube_preflight({},MockPath('/synthetic/roundcube'))
                result=None
                self.assertNotIn('SYNTHETIC_SECRET',str(failure.exception))
            else:
                result=probe.roundcube_preflight({},MockPath('/synthetic/roundcube'))
            command.assert_not_called();pg.assert_not_called();maria.assert_not_called();transport.assert_not_called()
        return result,reads,database_checks,connect,connection

    def test_known_debian_wrapper_resolves_literal_sqlite_with_readonly_integrity_check(self):
        self.assertEqual(hashlib.sha256(self.DEBIAN_WRAPPER.strip().encode()).hexdigest(),'c39d06fa29d90d8343d731f3a49a41670aeae04981090fb570284750fdd4e81a')
        for kind in ('sqlite','sqlite3'):
            for base,name in (('/var/lib/dbconfig-common/sqlite3/roundcube','roundcube'),('/var/lib/roundcube/db','roundcube'),('/var/lib/roundcube','roundcube.sqlite')):
                with self.subTest(kind=kind,base=base):
                    path=base+'/'+name
                    result,reads,checks,connect,connection=self.inspect_roundcube({'debian-db-roundcube.php':self.DEBIAN_WRAPPER,'debian-db.php':self.sqlite_config(kind,base,name)})
                    self.assertEqual(result,{'roundcube_sqlite_path':path,'roundcube_storage_preflight':'sqlite-readonly'})
                    self.assertEqual(reads,['/synthetic/roundcube/debian-db-roundcube.php','/synthetic/roundcube/debian-db.php'])
                    self.assertEqual(checks,[('regular',path),('symlink',path)])
                    connect.assert_called_once_with('file://'+path+'?mode=ro',uri=True)
                    connection.execute.assert_called_once_with('PRAGMA quick_check')

    def test_known_debian_wrapper_rejects_non_sqlite_before_open_without_executing_php(self):
        for kind in ('mysql','pgsql'):
            text=self.sqlite_config(kind)+"$dbpass='SYNTHETIC_SECRET';\nfile_put_contents('/synthetic/never-executed','SYNTHETIC_SECRET');\n"
            with self.subTest(kind=kind):
                _,reads,checks,connect,connection=self.inspect_roundcube({'debian-db-roundcube.php':self.DEBIAN_WRAPPER,'debian-db.php':text},error='configured non-SQLite')
                self.assertEqual(len(reads),2);self.assertEqual(checks,[]);connect.assert_not_called();connection.execute.assert_not_called()

    def test_known_debian_wrapper_does_not_adopt_unused_dbbasepath(self):
        invalid=[self.sqlite_config(base='/outside/supported')+"$dbbasepath='/var/lib/roundcube/db';\n",self.sqlite_config(base='/var/lib/roundcube/db').replace('$basepath','$dbbasepath')]
        for text in invalid:
            with self.subTest(text_kind='synthetic'):
                _,_,checks,connect,_=self.inspect_roundcube({'debian-db-roundcube.php':self.DEBIAN_WRAPPER,'debian-db.php':text},error='explicitly configured supported')
                self.assertEqual(checks,[]);connect.assert_not_called()
        result,_,_,_,_=self.inspect_roundcube({'debian-db-roundcube.php':self.DEBIAN_WRAPPER,'debian-db.php':self.sqlite_config()+"$dbbasepath='/var/lib/roundcube/db';\n"})
        self.assertEqual(result['roundcube_sqlite_path'],'/var/lib/dbconfig-common/sqlite3/roundcube/roundcube')

    def test_known_debian_wrapper_does_not_discard_basepath_for_absolute_database_name(self):
        _,_,checks,connect,_=self.inspect_roundcube({'debian-db-roundcube.php':self.DEBIAN_WRAPPER,'debian-db.php':self.sqlite_config(base='/outside/supported',name='/var/lib/roundcube/roundcube.sqlite')},error='explicitly configured supported')
        self.assertEqual(checks,[]);connect.assert_not_called()

    def test_known_debian_wrapper_requires_supported_literal_database_selection(self):
        for text in (None,'<?php\n',self.sqlite_config(base='/outside/supported'),self.sqlite_config().replace("$dbtype='sqlite3';",'$dbtype=$unknown;'),self.sqlite_config().replace("$dbname='roundcube';",'')):
            files={'debian-db-roundcube.php':self.DEBIAN_WRAPPER}
            if text is not None:files['debian-db.php']=text
            with self.subTest(config_kind='missing' if text is None else 'synthetic'):
                _,_,checks,connect,_=self.inspect_roundcube(files,error='explicitly configured supported')
                self.assertEqual(checks,[]);connect.assert_not_called()

    def test_changed_debian_wrapper_is_not_interpreted_as_known_package_template(self):
        variants=(self.DEBIAN_WRAPPER.replace('switch ($dbtype)','switch ($other)'),self.DEBIAN_WRAPPER+'\n// changed wrapper\n',self.DEBIAN_WRAPPER.replace('?mode=0640','?mode=0600'))
        for text in variants:
            with self.subTest(wrapper_hash=hashlib.sha256(text.encode()).hexdigest()):
                _,reads,checks,connect,_=self.inspect_roundcube({'debian-db-roundcube.php':text,'debian-db.php':self.sqlite_config()},error='explicitly configured supported')
                self.assertEqual(reads,['/synthetic/roundcube/debian-db-roundcube.php']);self.assertEqual(checks,[]);connect.assert_not_called()

    def test_static_roundcube_sqlite_dsn_retains_precedence(self):
        files={'debian-db-roundcube.php':"<?php\n$config['db_dsnw']='sqlite:////var/lib/roundcube/roundcube.sqlite';\n",'debian-db.php':self.sqlite_config(kind='mysql')}
        result,reads,_,connect,connection=self.inspect_roundcube(files)
        self.assertEqual(result['roundcube_sqlite_path'],'/var/lib/roundcube/roundcube.sqlite');self.assertEqual(len(reads),1)
        connect.assert_called_once_with('file:///var/lib/roundcube/roundcube.sqlite?mode=ro',uri=True);connection.execute.assert_called_once_with('PRAGMA quick_check')

    def test_standalone_roundcube_literals_retain_basepath_and_dbbasepath_compatibility(self):
        for variable in ('basepath','dbbasepath'):
            with self.subTest(variable=variable):
                text=self.sqlite_config(base='/var/lib/roundcube/db').replace('$basepath','$'+variable)
                result,_,_,connect,_=self.inspect_roundcube({'debian-db.php':text})
                self.assertEqual(result['roundcube_sqlite_path'],'/var/lib/roundcube/db/roundcube')
                connect.assert_called_once_with('file:///var/lib/roundcube/db/roundcube?mode=ro',uri=True)

    def test_known_debian_wrapper_keeps_regular_file_symlink_and_integrity_guards(self):
        files={'debian-db-roundcube.php':self.DEBIAN_WRAPPER,'debian-db.php':self.sqlite_config()}
        for options,message in (({'regular':False},'regular existing file'),({'symlink':True},'regular existing file'),({'integrity':False},'integrity check failed')):
            with self.subTest(options=options):
                _,_,_,connect,connection=self.inspect_roundcube(files,error=message,**options)
                if options.get('integrity') is False:
                    connect.assert_called_once_with('file:///var/lib/dbconfig-common/sqlite3/roundcube/roundcube?mode=ro',uri=True);connection.execute.assert_called_once_with('PRAGMA quick_check')
                else:connect.assert_not_called();connection.execute.assert_not_called()

class ForwardProbeTransportTests(unittest.TestCase):
    def login_post(self, status=201, transport_error=None):
        calls = []
        testcase = self
        class Response:
            def __init__(self, code):
                self.status = code
                self.reads = 0
            def read(self):
                self.reads += 1
                return b'offline-response'
        response = Response(status)
        class Opener:
            def open(self, request, data=None, timeout=None):
                calls.append((request, data, timeout))
                if isinstance(request, str):
                    testcase.assertEqual(request, 'https://127.0.0.1:7443/login')
                    testcase.assertEqual(data, b'email=offline%40example.test&password=offline-password')
                    testcase.assertEqual(timeout, 30)
                    return Response(200)
                testcase.assertEqual(request.full_url, 'https://127.0.0.1:7443/subscriptions/20/ftp')
                testcase.assertEqual(request.data, b'site_id=7&name=forwardfixture&password=offline-password&enabled=true')
                testcase.assertEqual(request.get_header('X-nakpanel-csrf'), hashlib.sha256(b'nakpanel-csrf-v1:offline-session').hexdigest())
                testcase.assertEqual(timeout, 60)
                if transport_error is not None:
                    raise transport_error
                return response
        opener = Opener()
        def build(*handlers):
            jar = next(handler.cookiejar for handler in handlers if isinstance(handler, probe.urllib.request.HTTPCookieProcessor))
            self.assertIsInstance(jar, probe.http.cookiejar.CookieJar)
            jar.set_cookie(probe.http.cookiejar.Cookie(0, 'nakpanel_session', 'offline-session', None, False,
                '127.0.0.1', False, False, '/', True, True, None, True, None, None, {}))
            return opener
        with patch.object(probe.urllib.request, 'build_opener', side_effect=build) as builder:
            post = probe.login({'admin_email': 'offline@example.test', 'admin_password': 'offline-password'})
        builder.assert_called_once()
        return post, response, calls

    def ftp_post(self, post):
        return post('subscriptions/20/ftp', {'site_id': 7, 'name': 'forwardfixture',
            'password': 'offline-password', 'enabled': 'true'})

    def test_login_post_accepts_created_and_existing_success_contracts(self):
        for status in (201, 200, 202, 303):
            with self.subTest(status=status):
                post, response, calls = self.login_post(status)
                self.assertEqual(self.ftp_post(post), b'offline-response')
                self.assertEqual(response.reads, 1)
                self.assertEqual(len(calls), 2)

    def test_login_post_rejects_unrecognized_success_and_error_statuses(self):
        for status in (204, 206, 299, 302, 307, 400, 401, 403, 404, 409, 422, 429, 500, 503):
            with self.subTest(status=status):
                post, response, calls = self.login_post(status)
                with self.assertRaises(RuntimeError) as caught:
                    self.ftp_post(post)
                self.assertEqual(caught.exception.args, ('fixture API mutation failed',))
                self.assertEqual(response.reads, 0)
                self.assertEqual(len(calls), 2)

    def test_login_post_preserves_transport_exception_identity(self):
        for error in (probe.urllib.error.HTTPError('https://127.0.0.1:7443/subscriptions/20/ftp', 400, 'offline', {}, None),
                      probe.urllib.error.HTTPError('https://127.0.0.1:7443/subscriptions/20/ftp', 503, 'offline', {}, None),
                      TimeoutError('offline')):
            with self.subTest(error_type=type(error).__name__):
                post, response, calls = self.login_post(transport_error=error)
                with self.assertRaises(type(error)) as caught:
                    self.ftp_post(post)
                self.assertIs(caught.exception, error)
                self.assertEqual(response.reads, 0)
                self.assertEqual(len(calls), 2)

    def test_rootless_uses_safe_child_cwd_from_inaccessible_parent(self):
        calls = []
        def transport(args, **kwargs):
            calls.append((args, kwargs))
            if kwargs.get('cwd', '/home/ubuntu') != '/':
                return subprocess.CompletedProcess(args, 125, '', 'cannot chdir to /home/ubuntu: Permission denied\n')
            return subprocess.CompletedProcess(args, 0, 'pulled\n', '')
        image = 'docker.io/library/nginx@sha256:' + '5' * 64
        with patch.object(probe.subprocess, 'run', side_effect=transport):
            self.assertEqual(probe.rootless({'subscription_id': 3, 'username': 'offline-tenant'}, 'pull', image), 'pulled')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], {'input': None, 'text': True, 'capture_output': True, 'env': None, 'timeout': 600, 'cwd': '/'})
        self.assertEqual(calls[0][0][:5], ['runuser', '-u', 'offline-tenant', '--', 'env'])
        self.assertEqual(calls[0][0][-3:], ['podman', 'pull', image])

    def test_other_probe_command_callers_keep_transport_and_errors(self):
        calls = []
        environment = {'OFFLINE': 'fixture'}
        def transport(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, ' value\n', '')
        with patch.object(probe.subprocess, 'run', side_effect=transport):
            self.assertEqual(probe.command(['offline-operation'], data='input', env=environment), 'value')
        self.assertEqual(calls, [(['offline-operation'], {'input': 'input', 'text': True, 'capture_output': True, 'env': environment, 'timeout': 600})])
        with patch.object(probe.subprocess, 'run', return_value=subprocess.CompletedProcess(['offline-operation'], 9, '', 'offline')):
            with self.assertRaises(RuntimeError) as caught:
                probe.command(['offline-operation'])
        self.assertEqual(caught.exception.args, ('guest operation failed: offline-operation',))

class ForwardCertificateStageTests(unittest.TestCase):
    def certificate_sandbox(self, program, config=None, mask=0o077, fail=None):
        import builtins, contextlib, io, types
        config = dict(source_vm='nakpanel-offline', run_token='offline-certificate-token',
            remote_src='/var/lib/nakpanel-qualification/offline-certificate-token/source',
            tls_hostname='fixture.invalid', domain='fixture.invalid', guest_ca='/etc/nakpanel/forward-fixture-ca.crt', site_id=7) if config is None else config
        commands=[]; owners={}; writes=[]; original_import=builtins.__import__
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            def disk(path): return base/str(path).lstrip('/')
            class GuestPath:
                def __init__(self, value):self.value=str(value)
                def __str__(self):return self.value
                def __truediv__(self, value):return GuestPath(self.value+'/'+str(value))
                def mkdir(self, **kwargs):disk(self).mkdir(**kwargs)
                def exists(self):return disk(self).exists()
                def read_text(self):return disk(self).read_text()
                def read_bytes(self):return disk(self).read_bytes()
                def write_text(self, value):writes.append(self.value);return disk(self).write_text(value)
                def write_bytes(self, value):writes.append(self.value);return disk(self).write_bytes(value)
            disk('/tmp').mkdir();source=config['remote_src']+'/deploy/install/sync-service-certificates.sh';disk(source).parent.mkdir(parents=True);disk(source).write_bytes(b'#!/bin/sh\n# authenticated test helper\n')
            def failure(args,kwargs,code,stream):
                raise subprocess.CalledProcessError(code,args,stderr=stream if kwargs.get('stderr')==subprocess.PIPE else None)
            def run(args,**kwargs):
                commands.append((tuple(args),dict(kwargs)))
                if fail is not None and fail[0](args):
                    if isinstance(fail[1],BaseException):raise fail[1]
                    failure(args,kwargs,fail[1],fail[2])
                if args[0]=='openssl':
                    target=args[args.index('-out')+1];disk(target).write_bytes(b'PRIVATE-TEST-KEY' if target.endswith('.key') else b'PUBLIC-TEST-CERT')
                    if target.endswith('.key'):os.chmod(disk(target),0o600)
                elif args[0]=='install':
                    mode=int(args[args.index('-m')+1],8);src,target=args[-2:];disk(target).parent.mkdir(parents=True,exist_ok=True);disk(target).write_bytes(disk(src).read_bytes());os.chmod(disk(target),mode)
                elif args[0]=='chown':owners[args[-1]]=args[1]
                elif args[0]=='runuser':
                    cert=args[args.index('--cert')+1];key=args[args.index('--key')+1]
                    if not disk(cert).stat().st_mode&0o004:failure(args,kwargs,1,b'read certificate: Permission denied\n')
                    if owners.get(key)!='nakpanel:nakpanel' or disk(key).stat().st_mode&0o077:failure(args,kwargs,1,b'private key permissions\n')
                elif args[0]=='/usr/local/libexec/nakpanel/sync-service-certificates':
                    if not disk(args[0]).exists():raise FileNotFoundError(2,'offline missing provisioned helper',args[0])
                else:self.assertIn(args[0],('update-ca-certificates','systemctl'))
                return subprocess.CompletedProcess(args,0,stderr=b'' if kwargs.get('stderr')==subprocess.PIPE else None)
            def check_output(args,**kwargs):
                commands.append((tuple(args),dict(kwargs)))
                if fail is not None and fail[0](args):
                    if isinstance(fail[1],BaseException):raise fail[1]
                    failure(args,kwargs,fail[1],fail[2])
                self.assertEqual(args[:5],['runuser','-u','postgres','--','psql'])
                return 'custom:active\n'.strip()+'\n' if 'tls_issuer' in args[-1] else 'fixture.invalid\n'
            fake=types.SimpleNamespace(run=run,check_output=check_output,DEVNULL=subprocess.DEVNULL,PIPE=subprocess.PIPE,CalledProcessError=subprocess.CalledProcessError,CompletedProcess=subprocess.CompletedProcess)
            def imported(name,globals=None,locals=None,fromlist=(),level=0):
                if name=='subprocess':return fake
                if name=='pathlib':return types.SimpleNamespace(Path=GuestPath)
                if name=='os':return types.SimpleNamespace(chmod=lambda path,mode:os.chmod(disk(path),mode))
                if name=='time':return types.SimpleNamespace(sleep=lambda seconds:None)
                return original_import(name,globals,locals,fromlist,level)
            namespace={'__name__':'__main__','__file__':'<offline-certificate-boundary>','__builtins__':dict(vars(builtins),__import__=imported)}
            out=io.StringIO();err=io.StringIO();error=None;oldmask=os.umask(mask)
            try:
                with patch.object(sys,'stdin',io.StringIO(json.dumps(config))),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                    try:exec(compile(program,'<offline-certificate-boundary>','exec'),namespace)
                    except Exception as caught:error=caught
            finally:os.umask(oldmask)
            root='/tmp/nakpanel-forward-certs-'+config['run_token'];leaf=disk(root+'/site.crt');key=disk(root+'/site.key');installed=disk('/usr/local/libexec/nakpanel/sync-service-certificates')
            return types.SimpleNamespace(error=error,stdout=out.getvalue(),stderr=err.getvalue(),commands=commands,
                leaf_mode=leaf.stat().st_mode&0o777 if leaf.exists() else None,key_mode=key.stat().st_mode&0o777 if key.exists() else None,
                helper_installed=installed.exists(),helper_mode=installed.stat().st_mode&0o777 if installed.exists() else None,
                helper_bytes_match=installed.exists() and installed.read_bytes()==disk(source).read_bytes(),writes=writes)

    def actual_certificate_program(self):
        with patch.object(fixture,'guest',side_effect=lambda config,vm,program:program):return fixture.certificates({'source_vm':'nakpanel-offline'})

    def test_certificate_public_leaf_readable_and_private_key_stays_private(self):
        result=self.certificate_sandbox(self.actual_certificate_program())
        self.assertIsNone(result.error)
        self.assertEqual((result.leaf_mode,result.key_mode),(0o644,0o600))

    def test_certificate_provisions_only_required_optional_service_helper(self):
        result=self.certificate_sandbox(self.actual_certificate_program(),mask=0o022)
        self.assertIsNone(result.error)
        self.assertTrue(result.helper_installed);self.assertTrue(result.helper_bytes_match);self.assertEqual(result.helper_mode,0o755)
        provision=[a for a,k in result.commands if a[0]=='install' and a[-1].startswith('/usr/local/libexec/')]
        self.assertEqual(len(provision),1);self.assertEqual(provision[0][-1],'/usr/local/libexec/nakpanel/sync-service-certificates')
        self.assertFalse(any('enable' in a or 'daemon-reload' in a for a,k in result.commands))


class ForwardContainerNetworkTests(unittest.TestCase):
    @contextlib.contextmanager
    def network_fixture(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);proc=root/'proc';proc.mkdir();ns=proc/'42/ns';ns.mkdir(parents=True);(ns/'net').write_text('container namespace')
            (proc/'self/ns').mkdir(parents=True);(proc/'self/ns/net').write_text('host namespace');(root/'netns').mkdir();os.link(ns/'net',root/'netns/fixture')
            def process(pid,flags=None,target=None):
                entry=proc/str(pid);entry.mkdir(exist_ok=True)
                (entry/'stat').write_text(str(pid)+' (offline process) S '+' '.join(['0']*18+['12345'])+'\n')
                if flags is not None:
                    (entry/'root').symlink_to('/');(entry/'exe').symlink_to('/usr/bin/slirp4netns');args=['/usr/bin/slirp4netns']+flags+['--netns-type=path',str(target or root/'netns/fixture'),'tap0'];(entry/'cmdline').write_bytes(b'\0'.join(x.encode() for x in args)+b'\0')
                return entry
            process(42);helper=process(101,['--disable-host-loopback','--outbound-addr=lo']);c={'username':'offline','oci_id':7,'image_ref':'fixed-image','oci_digest':'sha256:'+'d'*64,'oci_image_id':'a'*64,'images':[],'marker':'canary','application_secret':'secret'}
            observed={'State':{'Running':True,'Pid':42},'HostConfig':{'NetworkMode':'slirp4netns'},'Image':'sha256:'+'a'*64}
            with patch.object(probe.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid())):
                yield SimpleNamespace(root=root,proc=proc,helper=helper,config=c,observed=observed,process=process)
    def check_network(self,row):
        return probe.container_network(row.config,row.observed,row.proc)
    def test_noble_inspect_shape_passes_only_with_actual_isolated_helper(self):
        with self.network_fixture() as row:
            def rootless(c,*args):
                if args[0]=='inspect':return json.dumps([row.observed])
                if args[0]=='image':return c['oci_digest']
                return c['marker'] if args[-1]=='/forward-data/forward-canary' else c['application_secret']
            def command(args,*a,**kw):return 'LISTEN 0 0 127.0.0.1:12345' if args[0]=='ss' else ''
            checker=getattr(probe,'container_network',None)
            defaults=patch.object(checker,'__defaults__',(row.proc,)) if checker else contextlib.nullcontext()
            with defaults,patch.object(probe,'container_limits'),patch.object(probe,'rootless',side_effect=rootless),patch.object(probe,'pg',side_effect=lambda q:'fixed-container' if 'container_name' in q else '12345'),patch.object(probe,'command',side_effect=command):
                error=None
                try:probe.podman_live(row.config)
                except RuntimeError as caught:error=str(caught)
                self.assertIsNone(error,'valid Noble inspect/runtime shape rejected: '+str(error))
    def test_helper_mount_namespace_view_is_used(self):
        with self.network_fixture() as row:
            mount=row.root/'helper-mount';(mount/'run/helper-only').mkdir(parents=True)
            os.link(row.proc/'42/ns/net',mount/'run/helper-only/netns')
            (row.helper/'root').unlink();(row.helper/'root').symlink_to(mount)
            args=['/usr/bin/slirp4netns','--disable-host-loopback','--outbound-addr=lo','--netns-type=path','/run/helper-only/netns','tap0']
            (row.helper/'cmdline').write_bytes(b'\0'.join(x.encode() for x in args)+b'\0')
            with patch.object(subprocess,'run',side_effect=AssertionError('no extra command')):self.check_network(row)
    def test_running_pid_owner_and_private_namespace_are_required(self):
        from types import SimpleNamespace
        for edit in ('stopped','pid-bool','pid-zero','owner','host-netns','host-mode'):
            with self.subTest(edit=edit),self.network_fixture() as row:
                if edit=='stopped':row.observed['State']['Running']=False
                if edit=='pid-bool':row.observed['State']['Pid']=True
                if edit=='pid-zero':row.observed['State']['Pid']=0
                if edit=='host-mode':row.observed['HostConfig']['NetworkMode']='host'
                if edit=='host-netns':(row.proc/'42/ns/net').unlink();os.link(row.proc/'self/ns/net',row.proc/'42/ns/net')
                owner=patch.object(probe.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.getuid()+1)) if edit=='owner' else contextlib.nullcontext()
                with owner,patch.object(subprocess,'run',side_effect=AssertionError('no extra command')):
                    with self.assertRaises(RuntimeError):self.check_network(row)
    def test_effective_runtime_flags_are_exact_and_never_inferred_from_intent(self):
        for flags in ([],['--disable-host-loopback'],['--outbound-addr=lo'],['--disable-host-loopback','--outbound-addr=eth0'],['--disable-host-loopback','--outbound-addr=lo','--outbound-addr=eth0'],['--disable-host-loopback=false','--outbound-addr=lo'],['--disable-host-loopback','--disable-host-loopback','--outbound-addr=lo']):
            with self.subTest(flags=flags),self.network_fixture() as row:
                row.observed['Config']={'CreateCommand':['podman','create','--network','slirp4netns:allow_host_loopback=false,outbound_addr=lo']}
                args=['/usr/bin/slirp4netns']+flags+['--netns-type=path',str(row.root/'netns/fixture'),'tap0'];(row.helper/'cmdline').write_bytes(b'\0'.join(x.encode() for x in args)+b'\0')
                with self.assertRaisesRegex(RuntimeError,'flags'):self.check_network(row)
    def test_exact_executable_namespace_and_unique_helper_are_required(self):
        for edit in ('executable','foreign-netns','duplicate'):
            with self.subTest(edit=edit),self.network_fixture() as row:
                if edit=='executable':(row.helper/'exe').unlink();(row.helper/'exe').symlink_to('/tmp/slirp4netns')
                if edit=='foreign-netns':(row.root/'netns/fixture').unlink();(row.root/'netns/fixture').write_text('unrelated')
                if edit=='duplicate':row.process(102,['--disable-host-loopback','--outbound-addr=lo'])
                with self.assertRaisesRegex(RuntimeError,'helper'):self.check_network(row)
    def test_churn_scan_and_read_bounds_fail_closed(self):
        for edit in ('gone','oversize','scan','changed','start-time','netns-changed'):
            with self.subTest(edit=edit),self.network_fixture() as row:
                readlink=probe.os.readlink;scandir=probe.os.scandir;seen=[];closed=[]
                def link(path,*args,**kw):
                    if str(path)==str(row.helper/'exe'):
                        seen.append(path)
                        if edit=='gone' and len(seen)>1:raise FileNotFoundError(2,'offline churn')
                        if edit=='changed' and len(seen)>1:return '/tmp/foreign'
                        if edit=='start-time' and len(seen)==2:(row.helper/'stat').write_text((row.helper/'stat').read_text().replace('12345','12346'))
                        if edit=='netns-changed' and len(seen)==2:(row.root/'netns/fixture').unlink();(row.root/'netns/fixture').write_text('changed namespace')
                    return readlink(path,*args,**kw)
                class Entries:
                    def __enter__(self):return iter([row.proc/'42']*4097)
                    def __exit__(self,*args):closed.append(True)
                def scan(path):return Entries() if path==row.proc and edit=='scan' else scandir(path)
                if edit=='oversize':(row.helper/'cmdline').write_bytes(b'x'*16385)
                with patch.object(probe.os,'readlink',side_effect=link),patch.object(probe.os,'scandir',side_effect=scan),patch.object(subprocess,'run',side_effect=AssertionError('no extra command')):
                    with self.assertRaises(RuntimeError):self.check_network(row)
                if edit=='scan':self.assertEqual(closed,[True])


if __name__ == '__main__': unittest.main()
