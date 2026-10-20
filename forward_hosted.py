#!/usr/bin/env python3
"""Fixed candidate26 hosted fixture. Inert until separately root-bound admission.

No import-time actions. The trusted workflow revision and out-of-band admission
SHA are the entry trust roots; this is not protection from replacement of them.
"""
import sys
sys.dont_write_bytecode=True
import argparse, hashlib, json, math, os, platform, re, signal, stat, subprocess, tarfile, tempfile, time, zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

COMMIT='1627bba3c681a884255eb91452dbba74a43ebbdc'
TREE='fc003d27bc7e0fc13d095a4ebc464b17471dc26f'
ROOT_BASELINES={'native24':'dcefa079e44d23d1f6fc9514b32f1be399d3bc7c89190e1f8028dd5cf17c8a18','native26':'f230cba666f3edbdc2fdca18a43e070d13d5b53fbe9fdd10c6aae2e4cabf4a3d','required_ci':'d020396446bb2368b90a7c146e3ff26749eb1aa27eb6b580b97757b58837918b','payload':'3dff375db5cb83a6afa2c54a07d76301a10087d8adaa319bebb108e93c91faf4'}
ACCEPTED_PAYLOAD={'manifest_sha256':'50a0cc9802629bcdecb50f26a64f0ec8e49a434856f3f3aabb8e36650e8a60cc','public_key_sha256':'043971dd64ac6b9868e3d9f6cf29c852548e8f32276822187c66c2d40656ba61','binaries':{'panel':'535185eb683942313793bcf833f6e71d481a0cf12149103711d1f0e68a0d9c5f','agent':'9dea11b8ddb98e0f21863747d50c5778ab6629b1406a2cb0971b876ccf12fd4c','panelctl':'44319f18d64575dc46afc48d24115634a81e63925a567d9420634cdaf212fc60'}}
CAPS={k:v*60 for k,v in {'artifact':15,'host':20,'images':20,'admit':1,'current':45,'phase28':15,'phase30':20,'negative_backup':15,'prepare':30,'negative_install':40,'negative_check':5,'positive':90,'cleanup':15}.items()}
TOTAL_SECONDS=342*60
SHA=re.compile(r'[a-f0-9]{64}')
BINARY_PATHS={'panel':'/usr/local/bin/nakpanel-panel','agent':'/usr/local/bin/nakpanel-agent','panelctl':'/usr/local/bin/panelctl'}
IMAGES={'24.04':('noble','20261017','04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94'),'26.04':('resolute','20260927','8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2')}
class Refusal(ValueError):pass
class Deadline(Refusal):pass
PREDICATES={'positive_preflight','positive_snapshot','positive_mail_data','positive_php_inventory','positive_restore_result','positive_restore_manifest','positive_database_import','positive_services','positive_stage_evidence','positive_target_reboot','terminal_outcomes'}
BOUNDARIES=set(CAPS)|{'setup','source','negative_target','positive_driver','positive_evidence','positive_preflight','positive_restore','positive_budget','positive_identity','positive_reboot','source_unchanged','publication','completed'}
PROOF_CONTEXTS={'current','phase28','phase30','negative_backup','prepare','positive_source','negative_target','positive_target'}
PREPARATION_STAGES={'read-only-preflight','local-input-generation','source-php-preparation-and-seed','roundcube-canary-seed','fixture-certificates','source-live-checks','freeze-for-backup','encrypted-backup','offline-export','complete'}
PREPARATION_EARLY={b'forward fixture failed: fixture command failed: bash\n':'EARLY_IDENTITY_COMMAND',b'forward fixture failed: fixture command failed: multipass\n':'EARLY_SOURCE_PREFLIGHT_COMMAND'}
PREPARATION_ERRORS={'ValueError':'value','RuntimeError':'runtime','OSError':'io','FileNotFoundError':'io','PermissionError':'io','TimeoutExpired':'timeout','JSONDecodeError':'json','KeyError':'key','TypeError':'type','UnicodeDecodeError':'encoding'}

PREFLIGHT_HELPER_SHA='7224534e0fed25a1d358f8e812fdea9820ab61c9cf6f4076e2d1da40abd0222c'
PREFLIGHT_PROBE_SHA='3bf4432a9ffa119066af1df808c67e971989b6ae8fd82f87a54047c3205011c7'
PREFLIGHT_PREFIX='NAKPANEL_FORWARD_PREFLIGHT_V1:'
PREFLIGHT_SITES={'command':(28,32),'pg':(35,36),'discover':(95,109),'roundcube_preflight':(219,249),'active_php_plans':(351,354),'php_offers':(357,370),'php_offers.<genexpr>':(365,370),'php_offers.<setcomp>':(370,370),'fixture_php_inventory':(373,384),'assert_fixture_php_inventory':(387,414),'assert_fixture_php_inventory.<dictcomp>':(392,392),'assert_fixture_php_inventory.<genexpr>':(389,389),'assert_fixture_php_inventory.<setcomp>':(393,403),'plan_needs_php85':(470,473),'plan_needs_php85.<genexpr>':(472,472),'assert_fixture_entitlements':(476,481),'assert_fixture_entitlements.<genexpr>':(480,480),'fixture_image':(521,530),'source_preflight':(537,545),'source_preflight.<dictcomp>':(544,544),'source_preflight.<genexpr>':(542,542)}
PREPARE_LAUNCHER="import runpy,sys;scope=runpy.run_path(sys.argv[1],run_name='nakpanel_prepare_observer');scope['observed_qualifier_prepare'](*sys.argv[2:])"


# Independent qualifier identity; original source26 pins above remain unchanged.
ORIGINAL_HELPERS_SHA='7d88c068b43a2a2a002ae808401b57a8036ab0252b6ae2b224c5a9db8700a7e4'
QUALIFIER_PROBE_SHA='1fa03999f12fc7a3f0bc4bd07ee0afc04d5371c53824538e9496bf31fb6b68f8'
QUALIFIER_FILES={'qualifier-probe.py':('1fa03999f12fc7a3f0bc4bd07ee0afc04d5371c53824538e9496bf31fb6b68f8',68415),'qualifier-tests.py':('9c0e75dda3e8e03990ed36eaaf889da40a8a2f9d181c440c97f30dd86ab0ac16',80151),'qualifier-delivery.patch':('b1d360f3c834ed5fe581180dfea9eb78fe8b9b237e653e09c9495fe2a6a3e493',11530)}
QUALIFIER_IDENTITY={'runtime_source_commit':COMMIT,'runtime_source_tree':TREE,'qualifier_commit':'a35a92ea987e6ff9d04e4d321a12e28642093642','original_probe_sha256':PREFLIGHT_PROBE_SHA,'qualifier_probe_sha256':QUALIFIER_PROBE_SHA,'original_test_sha256':'55199edf2e51dd5acdd83be9d45f8157ca6a67684b9825e247f9716945dc0d76','delivery_test_sha256':QUALIFIER_FILES['qualifier-tests.py'][0],'delivery_patch_sha256':QUALIFIER_FILES['qualifier-delivery.patch'][0],'runtime_assets_changed':False}
QUALIFIER_GIT_BLOBS={'qualifier-probe.py':'21db6b0c69b0878d0e2a1c9a50cdf6454e080421','qualifier-tests.py':'9fa43cef416d02e0b0d4b13b74506f351dd9856e'}
QUALIFIER_IDENTITY.update(qualifier_parent_commit=COMMIT,qualifier_tree='96c8f8962096cbf809bf372bce73a9390e3be137')
QUALIFIER_PREFIX='NAKPANEL_FORWARD_QUALIFIER_V1:'
QUALIFIER_ACTIONS={'source-preflight':('source_preflight',1),'seed':('seed',2)}
QUALIFIER_SITES={'PlanEditor': (261, 288), 'PlanEditor.__init__': (262, 263), 'PlanEditor.handle_data': (275, 277), 'PlanEditor.handle_endtag': (278, 288), 'PlanEditor.handle_endtag.<genexpr>': (287, 287), 'PlanEditor.handle_endtag.<listcomp>': (285, 285), 'PlanEditor.handle_starttag': (264, 274), 'active_php_plans': (360, 363), 'assert_fixture_entitlements': (485, 490), 'assert_fixture_entitlements.<genexpr>': (489, 489), 'assert_fixture_php_inventory': (396, 423), 'assert_fixture_php_inventory.<dictcomp>': (401, 401), 'assert_fixture_php_inventory.<genexpr>': (398, 398), 'assert_fixture_php_inventory.<setcomp>': (402, 412), 'assert_php_only_preview': (347, 352), 'assert_php_only_preview.<genexpr>': (352, 352), 'assert_plan_only_php_changed': (313, 325), 'assert_plan_only_php_changed.masked': (314, 324), 'assert_plan_php_result': (355, 357), 'assert_snapshot_only_php_changed': (426, 457), 'assert_snapshot_only_php_changed.<lambda>': (456, 456), 'assert_snapshot_only_php_changed.<lambda>.<setcomp>': (456, 456), 'assert_snapshot_only_php_changed.legacy_php': (427, 429), 'assert_snapshot_only_php_changed.masked': (430, 446), 'cache_target_images': (188, 197), 'cli': (54, 59), 'command': (28, 32), 'container_limits': (803, 814), 'container_limits.<genexpr>': (808, 814), 'create_fixture_container': (557, 577), 'discover': (95, 109), 'fixture_catalog_slug': (542, 543), 'fixture_image': (530, 539), 'fixture_php_inventory': (382, 393), 'freeze': (921, 928), 'frozen': (913, 918), 'image_inventory': (200, 208), 'install_target_identities': (128, 185), 'install_target_identities.<dictcomp>': (131, 132), 'install_target_identities.<genexpr>': (141, 143), 'install_target_identities.<listcomp>': (149, 150), 'intent_projections': (738, 763), 'live': (848, 861), 'login': (71, 92), 'login.<genexpr>': (79, 79), 'login.<lambda>': (91, 91), 'login.post': (84, 90), 'managed_writers': (211, 216), 'managed_writers.<listcomp>': (215, 215), 'maria': (39, 47), 'normalize_active_plans': (493, 527), 'normalize_active_plans.<genexpr>': (498, 498), 'normalize_active_plans.<listcomp>': (496, 509), 'normalize_site_php': (610, 642), 'normalize_site_php.<listcomp>': (612, 612), 'normalized_plan_form': (291, 300), 'normalized_plan_form.<listcomp>': (293, 300), 'pg': (35, 36), 'php_application_form': (594, 607), 'php_application_form.<dictcomp>': (604, 606), 'php_application_form.<genexpr>': (596, 603), 'php_normalization_state': (580, 591), 'php_offers': (366, 379), 'php_offers.<genexpr>': (374, 379), 'php_offers.<setcomp>': (379, 379), 'plan_contract': (303, 310), 'plan_form_contract': (328, 330), 'plan_form_contract.<genexpr>': (330, 330), 'plan_needs_php85': (479, 482), 'plan_needs_php85.<genexpr>': (481, 481), 'plan_php_form': (333, 337), 'plan_php_form.<genexpr>': (336, 336), 'plan_php_form.<listcomp>': (337, 337), 'plan_php_response': (340, 344), 'podman_live': (817, 836), 'podman_live.<genexpr>': (829, 829), 'prepare_fixture_capabilities': (645, 671), 'prepare_fixture_capabilities.<genexpr>': (661, 661), 'quote': (50, 51), 'refresh_synced_php_snapshots': (460, 476), 'refresh_synced_php_snapshots.<dictcomp>': (463, 463), 'refresh_synced_php_snapshots.<genexpr>': (475, 475), 'rootless': (112, 117), 'roundcube_preflight': (219, 258), 'seed': (674, 735), 'seed.<genexpr>': (694, 694), 'snapshot': (766, 800), 'snapshot.<dictcomp>': (770, 775), 'snapshot.<genexpr>': (787, 792), 'snapshot.<listcomp>': (772, 774), 'source_preflight': (546, 554), 'source_preflight.<dictcomp>': (553, 553), 'source_preflight.<genexpr>': (551, 551), 'subordinate_row': (121, 125), 'subordinate_row.<listcomp>': (122, 122), 'tls': (864, 910), 'tls.<genexpr>': (894, 894), 'tls.LoopbackIMAP': (883, 886), 'tls.LoopbackIMAP._create_socket': (884, 886), 'wait': (62, 68), 'worker_secret_digest': (840, 845), 'worker_secret_digest.<genexpr>': (842, 842)}


# Exact captured text is an observation, not authenticated emitter/cause evidence.
SOURCE_LOG_SOURCES={'COMMON': ('deploy/multipass/common.sh', 'ec22749e3122d5182f79a0ce77af8f0eb1342611a00227fa06b2076ddc71ef8d', 21374, 'app', ('current', 'phase28', 'phase30')),
 'CURRENT_INSTALL': ('deploy/multipass/current-install-verify.sh',
                     'bdd1c43ee410417e6beef31bd58f7d7ab9bfa27f452fb41e09848aefc494f931',
                     15853,
                     'app',
                     ('current',)),
 'INSTALL_INSTALL': ('deploy/install/install.sh', '3b53c29ab1353161471d9aa1e0520f2aa897f4882ec741555efd1538937cef09', 37625, 'bundle', ('current', 'phase30')),
 'INSTALL_NGINX_SERVER_NAMES_INSTALL': ('deploy/install/nginx-server-names-install.sh',
                                        '6bdf1c02438644ec8596ae121123c3cf6ed2fac73b6c78e489a98b361da650c7',
                                        1395,
                                        'bundle',
                                        ('current', 'phase30')),
 'INSTALL_NOBLE_ROUNDCUBE': ('deploy/install/noble-roundcube.sh',
                             '5d929d43e396b114e8144ca3da0ed17f8f34e6653ab66aa24c5d0b051ed0d1fc',
                             2216,
                             'bundle',
                             ('current', 'phase30')),
 'INSTALL_PHASE18_INSTALL': ('deploy/install/phase18-install.sh',
                             'd84d3da3154cfea71aaa1932975b113943c67e4953e47f6e1f17fc3d5977f383',
                             5661,
                             'bundle',
                             ('current', 'phase30')),
 'INSTALL_PHASE21_25_INSTALL': ('deploy/install/phase21-25-install.sh',
                                '05dbb67fbe16dd72011969f013db127749bd15028a244157c26e2db07358fcdd',
                                5492,
                                'bundle',
                                ('current', 'phase28', 'phase30')),
 'INSTALL_PHASE30_INSTALL': ('deploy/install/phase30-install.sh',
                             'd400f0eaa2006a11b851760a6a1ced5f8befa1433d1ae49905789bccd7a91629',
                             14637,
                             'bundle',
                             ('current', 'phase30')),
 'INSTALL_PHASE7_INSTALL': ('deploy/install/phase7-install.sh',
                            '83b4d4ad3531a33a1bc3d87363e1ac27b58e2871a5ba416032187a298cd71e49',
                            2366,
                            'bundle',
                            ('current', 'phase30')),
 'INSTALL_PHASE8_INSTALL': ('deploy/install/phase8-install.sh',
                            '5f63008aa5caeb10240593b89f048e0be24312a68f3862c3643bd9fadaf6f4b8',
                            3358,
                            'bundle',
                            ('current', 'phase30')),
 'INSTALL_PLATFORM': ('deploy/install/platform.sh',
                      '936d53c4e81745932ce080d0bcd949ca940fffeb0ed142562f1cee6a4ad6498d',
                      10615,
                      'bundle',
                      ('current', 'phase28', 'phase30')),
 'INSTALL_ROUNDCUBE': ('deploy/install/roundcube.sh',
                       '31fc48f4e620a69f0c3b79b604ac09ed9ecc106e2f5de4531f680375e416cb1c',
                       4532,
                       'bundle',
                       ('current', 'phase30')),
 'INSTALL_ROUNDCUBE_MAINTENANCE': ('deploy/install/roundcube-maintenance.sh',
                                   '3de782a3e7d83fc6cbaab625b1063319bcc74ae9e7e6564b1a171468a9c3a51c',
                                   2112,
                                   'bundle',
                                   ('current', 'phase30')),
 'INSTALL_STALWART': ('deploy/install/stalwart.sh', 'f58944eb7ef0457b38b8a8f151d635742fb6bd5044da8ac4df16fe25ce65fed1', 2695, 'bundle', ('current', 'phase30')),
 'PHASE28': ('deploy/multipass/phase28-verify.sh', '1e6f1914a058ea4f6d8c9379e64041b68a88acfdb70747c6c20e693ceac18085', 20582, 'app', ('phase28',)),
 'PHASE30': ('deploy/multipass/phase30-verify.sh', '0eec2968c35c6b51ba61c9f3ffb60d14b1e9efc54a5aca90884cc1c97a1b1ce1', 55826, 'app', ('phase30',)),
 'QUALIFICATION_ARTIFACTS_PY': ('deploy/multipass/qualification_artifacts.py',
                                '9cb0c090e84a6dd7e6aa2ca5667830c1a3b48ce5b0bc1a0244096c67778b09fb',
                                11961,
                                'app',
                                ('current', 'phase28', 'phase30')),
 'QUALIFICATION_ARTIFACTS_SH': ('deploy/multipass/qualification-artifacts.sh',
                                '8b7fadc09affa5cae07c5c66184d11a49bd77f8369b958eb42f7dfabcc3888b7',
                                6352,
                                'app',
                                ('current', 'phase28', 'phase30'))}
SOURCE_LOG_ENVELOPES=(('COMMON_L069', 'COMMON', 69, 'error', 'multipass is required'),
 ('COMMON_L116', 'COMMON', 116, 'error', 'multipass exec kept hanging after three attempts'),
 ('COMMON_L124', 'COMMON', 124, 'error', 'choose a VM name beginning with nakpanel- or run manual cleanup yourself'),
 ('COMMON_L134',
  'COMMON',
  134,
  'error',
  'expected signed release artifacts are missing, unsafe or differ from the selected host release; refusing source-build fallback'),
 ('COMMON_L150', 'COMMON', 150, 'error', 'unsupported qualification release/PHP provider'),
 ('COMMON_L151', 'COMMON', 151, 'error', 'explicit safe NAKPANEL_RUN_TOKEN is required'),
 ('COMMON_L157', 'COMMON', 157, 'error', 'source and DR VM names must differ'),
 ('COMMON_L186', 'COMMON', 186, 'error', 'guest identity requires Ubuntu'),
 ('COMMON_L237', 'COMMON', 237, 'error', 'cloud-init did not finish in time'),
 ('COMMON_L300', 'COMMON', 300, 'error', 'invalid qualification guest resource budget'),
 ('COMMON_L311', 'COMMON', 311, 'error', 'stale ownership or image evidence; use a new run token'),
 ('COMMON_L316', 'COMMON', 316, 'error', 'launched guest identity mismatch'),
 ('COMMON_L358', 'COMMON', 358, 'error', 'signed source destination differs from private run path'),
 ('COMMON_L362', 'COMMON', 362, 'error', 'NAKPANEL_REMOTE_SRC must be a direct child of /tmp named nakpanel-*'),
 ('COMMON_L469', 'COMMON', 469, 'error', 'legacy cleanup requires explicit maintenance mode'),
 ('CURRENT_INSTALL_L008', 'CURRENT_INSTALL', 8, 'error', 'install-only qualification requires the selected signed release'),
 ('CURRENT_INSTALL_L012', 'CURRENT_INSTALL', 12, 'error', 'install-only recovery qualification requires modern secure administrator setup'),
 ('CURRENT_INSTALL_L086', 'CURRENT_INSTALL', 86, 'error', 'current-install: physical MariaDB canary did not round trip'),
 ('CURRENT_INSTALL_L103', 'CURRENT_INSTALL', 103, 'error', 'public seed clients remain enabled'),
 ('CURRENT_INSTALL_L118', 'CURRENT_INSTALL', 118, 'error', 'current-install: invalid fixture owner token'),
 ('CURRENT_INSTALL_L126', 'CURRENT_INSTALL', 126, 'error', 'current-install: unsupported mail fixture profile'),
 ('CURRENT_INSTALL_L181', 'CURRENT_INSTALL', 181, 'error', 'current-install: owned fixture effective PHP/mail/webmail entitlement is unavailable'),
 ('CURRENT_INSTALL_L196', 'CURRENT_INSTALL', 196, 'error', 'current-install: owned fixture row or bootstrap domain already exists; refusing reuse'),
 ('CURRENT_INSTALL_L210', 'CURRENT_INSTALL', 210, 'error', 'current-install: owned plan is not ready with the required PHP/mail/webmail contract'),
 ('PHASE28_L070', 'PHASE28', 70, 'error', 'phase28: site fixture is unavailable'),
 ('PHASE28_L129', 'PHASE28', 129, 'error', 'phase28: rootless Podman does not use the managed network compatibility command'),
 ('PHASE28_L152', 'PHASE28', 152, 'error', 'unrelated UID can list application parents'),
 ('PHASE28_L153', 'PHASE28', 153, 'error', 'unrelated UID can traverse private secrets'),
 ('PHASE28_L154', 'PHASE28', 154, 'error', 'unrelated UID can read private secret'),
 ('PHASE28_L163', 'PHASE28', 163, 'error', 'phase28: container is not reachable through tenant nginx'),
 ('PHASE28_L173', 'PHASE28', 173, 'error', 'phase28: container endpoint is not reachable on guest loopback'),
 ('PHASE28_L175', 'PHASE28', 175, 'error', 'phase28: container endpoint is reachable through the VM address'),
 ('PHASE28_L188', 'PHASE28', 188, 'error', 'phase28: application egress is available despite the disabled entitlement'),
 ('PHASE28_L190', 'PHASE28', 190, 'error', 'phase28: subscription home is no longer root-owned'),
 ('PHASE28_L191', 'PHASE28', 191, 'error', 'phase28: subordinate UID range is missing'),
 ('PHASE28_L192', 'PHASE28', 192, 'error', 'phase28: subordinate GID range is missing'),
 ('PHASE28_L195', 'PHASE28', 195, 'error', 'phase28: mounted secret is not mode 0600'),
 ('PHASE28_L197', 'PHASE28', 197, 'error', 'phase28: application secret leaked into River arguments'),
 ('PHASE28_L212', 'PHASE28', 212, 'error', 'phase28: unhealthy candidate replaced the active revision'),
 ('PHASE28_L213', 'PHASE28', 213, 'error', 'phase28: rollback did not preserve tenant traffic'),
 ('PHASE28_L216', 'PHASE28', 216, 'error', 'phase28: failed candidate secret generation remains on disk'),
 ('PHASE28_L234', 'PHASE28', 234, 'error', 'phase28: retired application containers remain after healthy rollout'),
 ('PHASE28_L237', 'PHASE28', 237, 'error', 'phase28: retired application systemd units remain after healthy rollout'),
 ('PHASE28_L241', 'PHASE28', 241, 'error', 'phase28: retired application secret generations remain after healthy rollout'),
 ('PHASE28_L251', 'PHASE28', 251, 'error', 'phase28: container did not recover after reboot'),
 ('PHASE28_L260', 'PHASE28', 260, 'error', 'phase28: panel did not recover after reboot'),
 ('PHASE28_L268', 'PHASE28', 268, 'error', 'phase28: suspended site did not return 503'),
 ('PHASE28_L279', 'PHASE28', 279, 'error', 'phase28: managed Applications page exposes a deploy action'),
 ('PHASE28_L299', 'PHASE28', 299, 'error', 'phase28: bounded container logs endpoint is unavailable'),
 ('PHASE28_L301', 'PHASE28', 301, 'error', 'phase28: provider catalog workspace is missing'),
 ('PHASE28_L308', 'PHASE28', 308, 'error', 'phase28: removed application storage remains on disk'),
 ('PHASE28_L311', 'PHASE28', 311, 'error', 'phase28: removed application systemd generation remains installed'),
 ('PHASE28_L315', 'PHASE28', 315, 'error', 'phase28: removed application route still serves the former container'),
 ('PHASE30_L021', 'PHASE30', 21, 'error', 'phase30: dependency manifest cannot be read'),
 ('PHASE30_L023', 'PHASE30', 23, 'error', 'phase30: unsupported dependency manifest schema'),
 ('PHASE30_L025', 'PHASE30', 25, 'error', 'phase30: unsupported dependency profile'),
 ('PHASE30_L028', 'PHASE30', 28, 'error', 'phase30: dependency profile is missing'),
 ('PHASE30_L031', 'PHASE30', 31, 'error', 'phase30: exact dependency tool pins are required'),
 ('PHASE30_L159', 'PHASE30', 159, 'progress', 'phase30: install and prove the current worktree'),
 ('PHASE30_L198', 'PHASE30', 198, 'error', 'phase30: current panel is not healthy'),
 ('PHASE30_L266', 'PHASE30', 266, 'progress', 'phase30: create panel-owned Classic and Managed PHP fixtures'),
 ('PHASE30_L270', 'PHASE30', 270, 'error', 'phase30: admin login failed'),
 ('PHASE30_L292', 'PHASE30', 292, 'error', 'phase30: Phase 30 plan was not saved'),
 ('PHASE30_L311', 'PHASE30', 311, 'error', 'phase30: subscription system account is missing'),
 ('PHASE30_L345', 'PHASE30', 345, 'progress', 'phase30: install WordPress 7.1 through Classic hosting'),
 ('PHASE30_L464', 'PHASE30', 464, 'progress', 'phase30: back up and restore Classic files plus tracked MariaDB'),
 ('PHASE30_L467', 'PHASE30', 467, 'error', 'phase30: could not parse Classic backup id'),
 ('PHASE30_L502', 'PHASE30', 502, 'error', 'PHP 8.5 FPM workers did not run as the subscription account'),
 ('PHASE30_L506', 'PHASE30', 506, 'progress', 'phase30: prove quota and cross-subscription filesystem isolation'),
 ('PHASE30_L521', 'PHASE30', 521, 'error', 'phase30: Classic document root is not owned by the first subscription'),
 ('PHASE30_L529', 'PHASE30', 529, 'error', 'effective hard block quota is not numeric'),
 ('PHASE30_L530', 'PHASE30', 530, 'error', 'effective hard block quota is unlimited'),
 ('PHASE30_L585', 'PHASE30', 585, 'error', 'phase30: new hosted repositories remain unavailable'),
 ('PHASE30_L586', 'PHASE30', 586, 'error', 'phase30: rejected hosted source wrote intent'),
 ('PHASE30_L690', 'PHASE30', 690, 'progress', 'phase30: reject an unhealthy release and retain the active release'),
 ('PHASE30_L711', 'PHASE30', 711, 'error', 'phase30: unhealthy deployment replaced the active release'),
 ('PHASE30_L715', 'PHASE30', 715, 'progress', 'phase30: prove secret absence from durable/control-plane surfaces'),
 ('PHASE30_L729', 'PHASE30', 729, 'error', 'phase30: initial panel/agent journal capture is empty'),
 ('PHASE30_L748', 'PHASE30', 748, 'error', 'second subscription read managed application environment/state'),
 ('PHASE30_L768', 'PHASE30', 768, 'progress', 'phase30: suspend, reactivate, reboot, and reconcile'),
 ('PHASE30_L800', 'PHASE30', 800, 'error', 'phase30: pre-reboot panel/agent journal capture is empty'),
 ('PHASE30_L811', 'PHASE30', 811, 'error', 'phase30: could not parse system reconciliation run ID'),
 ('PHASE30_L822', 'PHASE30', 822, 'error', 'phase30: reboot changed the active managed release'),
 ('PHASE30_L828', 'PHASE30', 828, 'progress', 'phase30: verify PHP UI and product-boundary copy'),
 ('PHASE30_L844', 'PHASE30', 844, 'error', 'phase30: runtime inventory is missing the selected Composer version'),
 ('PHASE30_L845', 'PHASE30', 845, 'error', 'phase30: runtime inventory is missing the selected WP-CLI version'),
 ('PHASE30_L883', 'PHASE30', 883, 'error', 'phase30: final panel/agent journal capture is empty'),
 ('INSTALL_INSTALL_L018', 'INSTALL_INSTALL', 18, 'error', 'install.sh must be run as root'),
 ('INSTALL_INSTALL_L089', 'INSTALL_INSTALL', 89, 'error', '--rollback-schema must be auto or manual'),
 ('INSTALL_INSTALL_L093', 'INSTALL_INSTALL', 93, 'error', '--restore requires --backup-key-file'),
 ('INSTALL_INSTALL_L125', 'INSTALL_INSTALL', 125, 'error', 'platform: --bundle requires --release-public-key and excludes --bin-dir'),
 ('INSTALL_INSTALL_L137', 'INSTALL_INSTALL', 137, 'error', 'development bundle requires explicit test-run environment opt-in'),
 ('INSTALL_INSTALL_L148', 'INSTALL_INSTALL', 148, 'error', 'VERSION file is empty'),
 ('INSTALL_INSTALL_L180', 'INSTALL_INSTALL', 180, 'error', 'an existing installation was detected; use --upgrade (or --force to reinstall fresh)'),
 ('INSTALL_INSTALL_L186', 'INSTALL_INSTALL', 186, 'error', 'platform: new Surý provider enrollment requires a fresh installation'),
 ('INSTALL_INSTALL_L206', 'INSTALL_INSTALL', 206, 'error', 'aborted'),
 ('INSTALL_INSTALL_L242', 'INSTALL_INSTALL', 242, 'error', 'install.sh: timed out waiting for Ubuntu background package activity'),
 ('INSTALL_INSTALL_L273', 'INSTALL_INSTALL', 273, 'error', 'invalid pinned Go release'),
 ('INSTALL_INSTALL_L406',
  'INSTALL_INSTALL',
  406,
  'error',
  'platform: fresh Resolute bootstrap requires a new panel database; use --upgrade or explicit restore'),
 ('INSTALL_INSTALL_L434', 'INSTALL_INSTALL', 434, 'error', 'install.sh: agent failed before native bootstrap; bootstrap remains pending'),
 ('INSTALL_INSTALL_L443', 'INSTALL_INSTALL', 443, 'error', 'install.sh: agent did not become ready for the panel peer; bootstrap remains pending'),
 ('INSTALL_INSTALL_L526', 'INSTALL_INSTALL', 526, 'error', '--admin-email requires --admin-password-file'),
 ('INSTALL_INSTALL_L530', 'INSTALL_INSTALL', 530, 'error', 'administrator password file must be a non-empty regular file'),
 ('INSTALL_INSTALL_L640', 'INSTALL_INSTALL', 640, 'error', 'platform: fresh native bootstrap did not create a new database'),
 ('INSTALL_INSTALL_L739', 'INSTALL_INSTALL', 739, 'error', 'install.sh: pre-upgrade dump is unreadable; refusing to migrate'),
 ('INSTALL_INSTALL_L765', 'INSTALL_INSTALL', 765, 'error', 'install.sh: could not restore /etc/nakpanel from the backup set'),
 ('INSTALL_INSTALL_L778', 'INSTALL_INSTALL', 778, 'error', 'install.sh: no usable pre-upgrade dump; leaving the database untouched'),
 ('INSTALL_INSTALL_L782', 'INSTALL_INSTALL', 782, 'error', 'install.sh: pre-upgrade dump is unreadable; leaving the database untouched'),
 ('INSTALL_INSTALL_L797', 'INSTALL_INSTALL', 797, 'error', 'install.sh: CRITICAL: pre-upgrade database restore FAILED.'),
 ('INSTALL_INSTALL_L810', 'INSTALL_INSTALL', 810, 'error', 'install.sh: upgrade failed; applying automatic recovery'),
 ('INSTALL_INSTALL_L818', 'INSTALL_INSTALL', 818, 'error', 'install.sh: pre-migration failure before any backup was taken; nothing was changed.'),
 ('INSTALL_INSTALL_L824', 'INSTALL_INSTALL', 824, 'error', 'install.sh: post-migration failure; restoring database from pre-upgrade dump'),
 ('INSTALL_INSTALL_L826', 'INSTALL_INSTALL', 826, 'error', 'install.sh: database rollback did not run; the new schema is still in place.'),
 ('INSTALL_INSTALL_L827', 'INSTALL_INSTALL', 827, 'error', 'install.sh: keeping the new binaries (older ones cannot serve the migrated schema).'),
 ('INSTALL_INSTALL_L845', 'INSTALL_INSTALL', 845, 'error', 'install.sh: rollback did not converge; operator attention required.'),
 ('INSTALL_INSTALL_L857', 'INSTALL_INSTALL', 857, 'error', 'install.sh: schema migrated before the failure; new binaries kept.'),
 ('INSTALL_PLATFORM_L043', 'INSTALL_PLATFORM', 43, 'error', 'platform: the Surý opt-in requires Ubuntu 26.04/resolute'),
 ('INSTALL_PLATFORM_L048', 'INSTALL_PLATFORM', 48, 'error', 'platform: PHP provider must be native or sury'),
 ('INSTALL_PLATFORM_L107',
  'INSTALL_PLATFORM',
  107,
  'error',
  'platform: changing the installed PHP provider is unsupported; use a fresh target and reviewed migration'),
 ('INSTALL_PLATFORM_L120', 'INSTALL_PLATFORM', 120, 'error', 'platform: cannot establish absence of an existing panel database'),
 ('INSTALL_PLATFORM_L133',
  'INSTALL_PLATFORM',
  133,
  'error',
  'platform: existing unrecorded installation on Resolute; an in-place OS upgrade is unsupported; use qualified forward migration'),
 ('INSTALL_PLATFORM_L157', 'INSTALL_PLATFORM', 157, 'error', 'platform: PHP PPA is not permitted for this profile'),
 ('INSTALL_PLATFORM_L160', 'INSTALL_PLATFORM', 160, 'error', 'platform: PHP PPA must bind its signing key and exact noble suite'),
 ('INSTALL_PHASE7_INSTALL_L005', 'INSTALL_PHASE7_INSTALL', 5, 'error', 'phase7-install.sh must be run as root'),
 ('INSTALL_PHASE7_INSTALL_L059',
  'INSTALL_PHASE7_INSTALL',
  59,
  'error',
  'install /usr/local/bin/nakpanel-panel, /usr/local/bin/nakpanel-agent, and /usr/local/bin/panelctl before starting nakpanel services'),
 ('INSTALL_PHASE7_INSTALL_L068', 'INSTALL_PHASE7_INSTALL', 68, 'progress', 'Phase 7 packages and nakpanel services are installed.'),
 ('INSTALL_PHASE8_INSTALL_L005', 'INSTALL_PHASE8_INSTALL', 5, 'error', 'phase8-install.sh must be run as root'),
 ('INSTALL_PHASE8_INSTALL_L040',
  'INSTALL_PHASE8_INSTALL',
  40,
  'error',
  'Disk quota support is unavailable in the running kernel. Reboot into the installed kernel, then rerun the installer.'),
 ('INSTALL_PHASE8_INSTALL_L074', 'INSTALL_PHASE8_INSTALL', 74, 'error', 'could not find filesystem for /home'),
 ('INSTALL_PHASE8_INSTALL_L096', 'INSTALL_PHASE8_INSTALL', 96, 'progress', 'Phase 8 quota tooling is installed and nakpanel services restarted.'),
 ('INSTALL_PHASE18_INSTALL_L008', 'INSTALL_PHASE18_INSTALL', 8, 'error', 'phase18-install.sh must run as root'),
 ('INSTALL_PHASE21_25_INSTALL_L005', 'INSTALL_PHASE21_25_INSTALL', 5, 'error', 'phase21-25-install.sh must be run as root'),
 ('INSTALL_PHASE21_25_INSTALL_L122',
  'INSTALL_PHASE21_25_INSTALL',
  122,
  'error',
  'NAKPANEL_VALKEY_IMAGE must pin the official docker.io/valkey/valkey image by sha256 digest'),
 ('INSTALL_PHASE21_25_INSTALL_L142',
  'INSTALL_PHASE21_25_INSTALL',
  142,
  'progress',
  'Phase 21-25 hosting toolkit packages and agent configuration are installed.'),
 ('INSTALL_PHASE30_INSTALL_L005', 'INSTALL_PHASE30_INSTALL', 5, 'error', 'phase30-install.sh must be run as root'),
 ('INSTALL_PHASE30_INSTALL_L023', 'INSTALL_PHASE30_INSTALL', 23, 'error', 'ClamAV signature updater could not be paused safely'),
 ('INSTALL_PHASE30_INSTALL_L088',
  'INSTALL_PHASE30_INSTALL',
  88,
  'error',
  'ClamAV signatures are unavailable; run freshclam after fixing network or mirror access'),
 ('INSTALL_PHASE30_INSTALL_L099', 'INSTALL_PHASE30_INSTALL', 99, 'error', 'ClamAV signatures cannot be loaded by an unprivileged managed deployment scanner'),
 ('INSTALL_PHASE30_INSTALL_L141', 'INSTALL_PHASE30_INSTALL', 141, 'error', 'ClamAV update service does not retain the required public signature creation mask'),
 ('INSTALL_PHASE30_INSTALL_L145', 'INSTALL_PHASE30_INSTALL', 145, 'error', 'ClamAV signature updates could not be enabled'),
 ('INSTALL_PHASE30_INSTALL_L155', 'INSTALL_PHASE30_INSTALL', 155, 'error', 'ppa:ondrej/php was added without a Signed-By key binding'),
 ('INSTALL_PHASE30_INSTALL_L245', 'INSTALL_PHASE30_INSTALL', 245, 'error', 'composer self-update is disabled; use the nakpanel installer'),
 ('INSTALL_PHASE30_INSTALL_L263', 'INSTALL_PHASE30_INSTALL', 263, 'error', 'wp cli update is disabled; use the nakpanel installer'),
 ('INSTALL_PHASE30_INSTALL_L396', 'INSTALL_PHASE30_INSTALL', 396, 'progress', 'Phase 30 PHP runtimes, Composer, and WP-CLI are installed and validated.'),
 ('INSTALL_STALWART_L008', 'INSTALL_STALWART', 8, 'error', 'unsupported Stalwart host architecture'),
 ('INSTALL_STALWART_L011', 'INSTALL_STALWART', 11, 'error', 'Stalwart host/platform architecture mismatch'),
 ('INSTALL_STALWART_L037', 'INSTALL_STALWART', 37, 'error', 'Stalwart installation requires root'),
 ('INSTALL_ROUNDCUBE_L014', 'INSTALL_ROUNDCUBE', 14, 'error', 'Roundcube SHA-256 differs from pinned upstream release'),
 ('INSTALL_ROUNDCUBE_L021', 'INSTALL_ROUNDCUBE', 21, 'error', 'Roundcube signing key differs from pin'),
 ('INSTALL_ROUNDCUBE_L027', 'INSTALL_ROUNDCUBE', 27, 'error', 'Roundcube signature verification failed'),
 ('INSTALL_ROUNDCUBE_L072', 'INSTALL_ROUNDCUBE', 72, 'error', 'refusing to replace an existing unmanaged Roundcube directory'),
 ('INSTALL_ROUNDCUBE_MAINTENANCE_L010', 'INSTALL_ROUNDCUBE_MAINTENANCE', 10, 'error', 'unsupported Roundcube maintenance profile'),
 ('INSTALL_NGINX_SERVER_NAMES_INSTALL_L006', 'INSTALL_NGINX_SERVER_NAMES_INSTALL', 6, 'error', 'nginx-server-names-install.sh must run as root'),
 ('INSTALL_NGINX_SERVER_NAMES_INSTALL_L013', 'INSTALL_NGINX_SERVER_NAMES_INSTALL', 13, 'error', 'Refusing a symlink at the managed nginx configuration'),
 ('INSTALL_NGINX_SERVER_NAMES_INSTALL_L043',
  'INSTALL_NGINX_SERVER_NAMES_INSTALL',
  43,
  'progress',
  'Validated nginx hostname capacity configuration installed.'),
 ('COMMON_L004', 'COMMON', 4, 'error', 'Qualification requires GNU Bash 5 or newer.'),
 ('COMMON_L005', 'COMMON', 5, 'error', 'Install GNU Bash 5+ and invoke the qualification entry point using its explicit executable path.'),
 ('INSTALL_PLATFORM_L191', 'INSTALL_PLATFORM', 191, 'progress', 'platform: package transaction resolved for ubuntu-24.04/amd64'),
 ('INSTALL_INSTALL_L673', 'INSTALL_INSTALL', 673, 'progress', 'nakpanel 29.0.0 installed successfully.'),
 ('QUALIFICATION_ARTIFACTS_SH_L010', 'QUALIFICATION_ARTIFACTS_SH', 10, 'error', 'unsafe qualification token'),
 ('QUALIFICATION_ARTIFACTS_SH_L013', 'QUALIFICATION_ARTIFACTS_SH', 13, 'error', 'signed qualification source must use the token-bound private guest path'),
 ('QUALIFICATION_ARTIFACTS_SH_L032', 'QUALIFICATION_ARTIFACTS_SH', 32, 'error', 'selected host identity must be regular files'),
 ('QUALIFICATION_ARTIFACTS_PY_L028', 'QUALIFICATION_ARTIFACTS_PY', 28, 'error', 'ValueError: unsafe qualification token'),
 ('QUALIFICATION_ARTIFACTS_PY_L049', 'QUALIFICATION_ARTIFACTS_PY', 49, 'error', 'ValueError: host SHA256 is required before reading a transferred input'),
 ('QUALIFICATION_ARTIFACTS_PY_L123', 'QUALIFICATION_ARTIFACTS_PY', 123, 'error', 'ValueError: only the reviewed public qualification probes may be exposed'),
 ('QUALIFICATION_ARTIFACTS_PY_L130', 'QUALIFICATION_ARTIFACTS_PY', 130, 'error', 'ValueError: guest probe differs from the exact frozen host source'),
 ('QUALIFICATION_ARTIFACTS_PY_L166',
  'QUALIFICATION_ARTIFACTS_PY',
  166,
  'error',
  'ValueError: guest release does not match the exact selected manifest and trust anchor'),
 ('QUALIFICATION_ARTIFACTS_PY_L054', 'QUALIFICATION_ARTIFACTS_PY', 54, 'error', 'ValueError: transferred input must be a bounded regular file'),
 ('QUALIFICATION_ARTIFACTS_PY_L057', 'QUALIFICATION_ARTIFACTS_PY', 57, 'error', 'ValueError: transferred input size differs from frozen host input'),
 ('QUALIFICATION_ARTIFACTS_PY_L070', 'QUALIFICATION_ARTIFACTS_PY', 70, 'error', 'ValueError: transferred input differs from frozen host SHA256'),
 ('QUALIFICATION_ARTIFACTS_PY_L136',
  'QUALIFICATION_ARTIFACTS_PY',
  136,
  'error',
  'ValueError: public probe directory must be owned and read-only to other users'),
 ('QUALIFICATION_ARTIFACTS_PY_L197', 'QUALIFICATION_ARTIFACTS_PY', 197, 'error', 'ValueError: staged manifest differs from exact selected host release'),
 ('QUALIFICATION_ARTIFACTS_PY_L082', 'QUALIFICATION_ARTIFACTS_PY', 82, 'error', 'ValueError: qualification archive contains an unsafe entry'),
 ('QUALIFICATION_ARTIFACTS_PY_L087', 'QUALIFICATION_ARTIFACTS_PY', 87, 'error', 'ValueError: qualification archive contains a duplicate entry'),
 ('QUALIFICATION_ARTIFACTS_PY_L068', 'QUALIFICATION_ARTIFACTS_PY', 68, 'error', 'ValueError: transferred input grew during sealing'),
 ('QUALIFICATION_ARTIFACTS_PY_L066', 'QUALIFICATION_ARTIFACTS_PY', 66, 'error', 'ValueError: transferred input was truncated during sealing'))
SOURCE_LOG_TRAP_LINES={'PHASE28': [2,
             3,
             5,
             6,
             7,
             8,
             9,
             11,
             12,
             13,
             14,
             15,
             16,
             17,
             18,
             19,
             20,
             21,
             23,
             24,
             25,
             26,
             28,
             29,
             30,
             31,
             32,
             33,
             34,
             35,
             36,
             37,
             38,
             39,
             40,
             41,
             42,
             43,
             44,
             45,
             46,
             47,
             50,
             51,
             52,
             53,
             54,
             55,
             56,
             57,
             58,
             60,
             61,
             62,
             63,
             64,
             65,
             66,
             67,
             68,
             69,
             70,
             72,
             73,
             74,
             75,
             76,
             77,
             78,
             79,
             80,
             81,
             83,
             88,
             89,
             90,
             91,
             92,
             93,
             94,
             95,
             96,
             97,
             98,
             99,
             100,
             101,
             102,
             105,
             106,
             107,
             108,
             109,
             110,
             111,
             112,
             113,
             114,
             115,
             116,
             117,
             118,
             119,
             121,
             122,
             123,
             124,
             125,
             126,
             127,
             128,
             129,
             131,
             132,
             133,
             134,
             135,
             136,
             137,
             138,
             139,
             140,
             141,
             142,
             143,
             144,
             145,
             146,
             147,
             148,
             151,
             152,
             153,
             154,
             155,
             156,
             157,
             158,
             159,
             160,
             162,
             163,
             164,
             165,
             166,
             167,
             168,
             169,
             170,
             171,
             172,
             173,
             174,
             175,
             176,
             177,
             178,
             179,
             180,
             181,
             182,
             183,
             184,
             185,
             187,
             188,
             189,
             190,
             191,
             192,
             193,
             194,
             195,
             196,
             197,
             198,
             201,
             202,
             203,
             204,
             205,
             206,
             207,
             208,
             209,
             210,
             211,
             212,
             213,
             214,
             215,
             216,
             219,
             220,
             221,
             222,
             223,
             224,
             225,
             226,
             227,
             228,
             229,
             230,
             231,
             232,
             233,
             234,
             235,
             236,
             237,
             238,
             239,
             240,
             241,
             242,
             243,
             244,
             245,
             246,
             247,
             248,
             249,
             250,
             251,
             255,
             256,
             257,
             258,
             259,
             260,
             261,
             262,
             263,
             264,
             265,
             266,
             267,
             268,
             269,
             270,
             271,
             272,
             273,
             275,
             276,
             277,
             278,
             279,
             280,
             281,
             282,
             283,
             284,
             285,
             286,
             287,
             288,
             289,
             290,
             291,
             292,
             293,
             294,
             295,
             296,
             297,
             298,
             299,
             300,
             301,
             303,
             304,
             305,
             306,
             307,
             308,
             309,
             310,
             311,
             312,
             313,
             314,
             315,
             316,
             318],
 'PHASE30': [6,
             7,
             9,
             10,
             11,
             14,
             15,
             16,
             17,
             18,
             19,
             20,
             21,
             22,
             23,
             24,
             25,
             26,
             27,
             28,
             29,
             30,
             31,
             32,
             34,
             35,
             36,
             37,
             38,
             39,
             40,
             41,
             42,
             43,
             45,
             46,
             47,
             49,
             50,
             51,
             52,
             53,
             54,
             56,
             57,
             58,
             59,
             61,
             62,
             63,
             64,
             65,
             66,
             67,
             68,
             69,
             70,
             71,
             72,
             73,
             74,
             76,
             77,
             78,
             79,
             80,
             81,
             82,
             83,
             84,
             86,
             87,
             88,
             89,
             90,
             91,
             92,
             93,
             94,
             96,
             97,
             98,
             99,
             100,
             101,
             102,
             103,
             104,
             105,
             106,
             107,
             109,
             110,
             111,
             112,
             113,
             114,
             115,
             116,
             117,
             118,
             119,
             120,
             121,
             122,
             124,
             125,
             126,
             127,
             128,
             130,
             131,
             132,
             133,
             134,
             135,
             136,
             137,
             138,
             139,
             140,
             141,
             142,
             143,
             144,
             145,
             147,
             148,
             149,
             150,
             151,
             152,
             153,
             154,
             155,
             156,
             157,
             159,
             160,
             161,
             162,
             163,
             164,
             168,
             169,
             170,
             171,
             172,
             173,
             174,
             175,
             176,
             177,
             178,
             179,
             180,
             181,
             182,
             183,
             184,
             185,
             186,
             187,
             188,
             189,
             192,
             193,
             194,
             195,
             196,
             197,
             198,
             202,
             203,
             204,
             205,
             206,
             207,
             208,
             209,
             210,
             211,
             212,
             213,
             214,
             215,
             216,
             217,
             218,
             219,
             220,
             223,
             224,
             225,
             226,
             227,
             228,
             229,
             230,
             231,
             232,
             233,
             234,
             235,
             236,
             237,
             238,
             239,
             240,
             241,
             242,
             243,
             244,
             245,
             246,
             247,
             248,
             249,
             250,
             251,
             252,
             253,
             254,
             255,
             256,
             257,
             258,
             259,
             260,
             261,
             262,
             263,
             266,
             267,
             268,
             269,
             270,
             272,
             273,
             275,
             276,
             277,
             278,
             279,
             280,
             281,
             282,
             283,
             284,
             285,
             286,
             287,
             288,
             289,
             290,
             291,
             292,
             294,
             295,
             296,
             297,
             298,
             299,
             300,
             301,
             302,
             303,
             304,
             305,
             306,
             307,
             308,
             309,
             310,
             311,
             313,
             314,
             315,
             316,
             318,
             319,
             320,
             321,
             322,
             323,
             324,
             330,
             331,
             332,
             333,
             334,
             335,
             336,
             337,
             338,
             339,
             340,
             341,
             342,
             343,
             345,
             346,
             347,
             348,
             349,
             350,
             351,
             352,
             353,
             354,
             355,
             356,
             357,
             358,
             359,
             360,
             361,
             362,
             363,
             364,
             365,
             366,
             367,
             368,
             369,
             370,
             372,
             373,
             374,
             375,
             376,
             377,
             378,
             379,
             380,
             381,
             382,
             383,
             384,
             385,
             388,
             389,
             390,
             391,
             392,
             393,
             394,
             395,
             397,
             398,
             399,
             400,
             401,
             402,
             403,
             404,
             405,
             406,
             407,
             408,
             409,
             410,
             411,
             412,
             413,
             414,
             415,
             416,
             417,
             418,
             419,
             420,
             421,
             422,
             423,
             424,
             425,
             426,
             427,
             428,
             429,
             430,
             431,
             432,
             433,
             434,
             435,
             436,
             437,
             438,
             439,
             440,
             441,
             442,
             443,
             444,
             445,
             446,
             447,
             448,
             449,
             450,
             451,
             454,
             455,
             456,
             457,
             458,
             459,
             460,
             461,
             462,
             464,
             465,
             466,
             467,
             468,
             469,
             470,
             471,
             472,
             473,
             475,
             476,
             477,
             478,
             479,
             480,
             481,
             484,
             485,
             486,
             487,
             488,
             489,
             490,
             491,
             492,
             493,
             494,
             495,
             496,
             497,
             498,
             499,
             500,
             501,
             502,
             503,
             506,
             507,
             508,
             509,
             510,
             511,
             512,
             513,
             514,
             515,
             516,
             517,
             518,
             519,
             520,
             521,
             522,
             523,
             524,
             525,
             526,
             527,
             528,
             529,
             530,
             531,
             532,
             533,
             534,
             535,
             536,
             537,
             538,
             539,
             540,
             541,
             542,
             543,
             544,
             545,
             546,
             547,
             548,
             549,
             550,
             551,
             552,
             553,
             554,
             555,
             556,
             557,
             558,
             559,
             560,
             561,
             562,
             563,
             564,
             565,
             566,
             567,
             568,
             569,
             570,
             571,
             572,
             575,
             576,
             577,
             580,
             581,
             582,
             583,
             584,
             585,
             586,
             587,
             588,
             589,
             590,
             591,
             592,
             593,
             594,
             596,
             597,
             598,
             599,
             600,
             601,
             602,
             603,
             604,
             605,
             606,
             607,
             608,
             609,
             610,
             611,
             612,
             613,
             614,
             615,
             616,
             617,
             618,
             619,
             620,
             621,
             622,
             623,
             624,
             625,
             626,
             627,
             630,
             631,
             632,
             633,
             634,
             635,
             636,
             637,
             641,
             642,
             643,
             644,
             645,
             646,
             647,
             648,
             649,
             651,
             652,
             653,
             654,
             655,
             656,
             658,
             659,
             660,
             661,
             662,
             663,
             664,
             665,
             666,
             667,
             668,
             669,
             670,
             671,
             672,
             673,
             674,
             675,
             676,
             677,
             678,
             679,
             680,
             681,
             682,
             683,
             684,
             685,
             686,
             687,
             688,
             690,
             691,
             692,
             693,
             694,
             695,
             696,
             697,
             698,
             699,
             700,
             701,
             702,
             703,
             704,
             705,
             706,
             707,
             709,
             710,
             711,
             712,
             713,
             715,
             716,
             717,
             718,
             719,
             720,
             721,
             722,
             723,
             724,
             725,
             726,
             727,
             728,
             729,
             730,
             731,
             732,
             733,
             734,
             735,
             736,
             737,
             738,
             740,
             741,
             742,
             743,
             744,
             745,
             746,
             747,
             748,
             749,
             750,
             751,
             753,
             754,
             755,
             756,
             757,
             758,
             759,
             760,
             761,
             762,
             763,
             764,
             765,
             766,
             768,
             769,
             770,
             771,
             772,
             773,
             774,
             775,
             776,
             778,
             779,
             780,
             781,
             782,
             783,
             784,
             785,
             786,
             787,
             788,
             789,
             790,
             791,
             792,
             796,
             797,
             798,
             799,
             800,
             802,
             803,
             805,
             806,
             807,
             808,
             809,
             810,
             811,
             812,
             813,
             814,
             815,
             816,
             817,
             818,
             819,
             820,
             821,
             822,
             823,
             824,
             825,
             826,
             828,
             829,
             830,
             831,
             832,
             833,
             834,
             835,
             836,
             838,
             839,
             840,
             841,
             842,
             843,
             844,
             845,
             846,
             847,
             848,
             849,
             850,
             851,
             852,
             853,
             854,
             855,
             856,
             857,
             859,
             860,
             861,
             862,
             863,
             864,
             865,
             866,
             867,
             868,
             869,
             870,
             871,
             872,
             873,
             874,
             875,
             876,
             877,
             878,
             879,
             880,
             881,
             882,
             883,
             885,
             886,
             887,
             888,
             889,
             890,
             891,
             892,
             893,
             894,
             895,
             897,
             898,
             899]}

SERVICE_ALIASES={'panel':'nakpanel.service','agent':'nakpanel-agent.service','nginx':'nginx.service','postgresql':'postgresql.service','mariadb':'mariadb.service','named':'named.service','stalwart':'stalwart-mail.service','proftpd':'nakpanel-proftpd.service'}
CORE_SEVEN=tuple(v for k,v in SERVICE_ALIASES.items() if k!='proftpd')
CHECK_KEYS={'binary_inventory_matches','panel_matches','agent_matches','panelctl_matches','architecture_matches','profile_matches','version_matches','database_fingerprint_valid','boot_id_valid','units_predicate'}|set(SERVICE_ALIASES)
PREDICATES.update({'source_binary_inventory','source_architecture','source_profile','source_version','source_database_fingerprint','source_boot_id','source_units','trusted_file_metadata','host_owner_binding','input_pin_mismatch'}|{prefix+'_'+part for prefix in ('vm_list','cleanup_initial','cleanup_final') for part in ('object','errors','rows','absence')})
BOUNDARIES.update({'source_current_run','source_phase28_run','source_phase30_run','source_budget','proof_owner','proof_pins','proof_command','proof_json','proof_binaries','proof_architecture','proof_profile','proof_version','proof_database','proof_boot','proof_units','cleanup_group','cleanup_destroy'}|{prefix+'_'+part for prefix in ('vm_list','cleanup_initial','cleanup_final') for part in ('command','json','object','errors','rows','absence')})

def closed(value,allowed):return value if type(value) is str and value in allowed else 'UNKNOWN'


def source_log_unknown(context='UNKNOWN',ordinal=0):
    empty={'label':'UNKNOWN','source_sha256':'UNKNOWN','predicate':'UNKNOWN'}
    return {'context':closed(context,{'current','phase28','phase30'}),'command_ordinal':ordinal if type(ordinal) is int and 0<ordinal<=100000 else 0,'binding':'UNKNOWN','stdout_scope':'UNKNOWN','stderr_scope':'UNKNOWN','coverage':'FIXED_SOURCE_ENVELOPES_ONLY','error':dict(empty),'last_stage':dict(empty),'trap':dict(empty),'error_labels':[],'errors_truncated':False,'ambiguous':False}

def source_log_label(label,context,kind):
    for name,key,line,category,text in SOURCE_LOG_ENVELOPES:
        if name==label and category==kind and context in SOURCE_LOG_SOURCES[key][4]:return {'label':name,'source_sha256':SOURCE_LOG_SOURCES[key][1],'predicate':'FIXED_ERROR_ENVELOPE' if kind=='error' else 'FIXED_PROGRESS_ENVELOPE'}
    return {'label':'UNKNOWN','source_sha256':'UNKNOWN','predicate':'UNKNOWN'}

def source_phase_projection(value):
    if type(value) is not dict:return source_log_unknown()
    result=source_log_unknown(value.get('context'));ordinal=value.get('command_ordinal')
    if result['context']=='UNKNOWN' or value.get('binding')!='MATCHED_REAPED_FAILED_COMMAND' or type(ordinal) is not int or not 0<ordinal<=100000:return result
    result['binding']='MATCHED_REAPED_FAILED_COMMAND';result['command_ordinal']=ordinal
    for stream in ('stdout','stderr'):result[stream+'_scope']=closed(value.get(stream+'_scope'),{'FULL','TAIL'})
    for field,kind in (('error','error'),('last_stage','progress')):
        row=value.get(field);result[field]=source_log_label(row.get('label') if type(row) is dict else None,result['context'],kind)
    trap=value.get('trap');label=trap.get('label') if type(trap) is dict else None
    for key,lines in SOURCE_LOG_TRAP_LINES.items():
        if result['context']!=key.lower():continue
        for line in lines:
            if label==key+'_ERR_L'+str(line).zfill(3):result['trap']={'label':label,'source_sha256':SOURCE_LOG_SOURCES[key][1],'predicate':'REPORTED_ERR_SOURCE_LINE'}
    rows=value.get('error_labels')
    if type(rows) is list:
        for label in rows[-8:]:
            record=source_log_label(label,result['context'],'error')
            if record['label']!='UNKNOWN' and record['label']not in result['error_labels']:result['error_labels'].append(record['label'])
    result['errors_truncated']=value.get('errors_truncated') is True;result['ambiguous']=value.get('ambiguous') is True
    return result

def source_log_seal(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def source_log_source_bound(path,key):
    descriptor=None
    try:
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);before=os.fstat(descriptor);expected=SOURCE_LOG_SOURCES[key]
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_mode&0o022 or before.st_size!=expected[2]:return False
        with os.fdopen(descriptor,'rb',closefd=False) as stream:raw=stream.read(expected[2]+1)
        return len(raw)==expected[2] and digest(raw)==expected[1] and source_log_seal(before)==source_log_seal(os.fstat(descriptor))==source_log_seal(os.lstat(path))
    except Exception:return False
    finally:
        if descriptor is not None:os.close(descriptor)

def source_log_tail(root,ordinal,stage,stream):
    if type(ordinal) is not int or not 0<ordinal<=100000 or closed(stage,{'current','phase28','phase30'})=='UNKNOWN' or closed(stream,{'stdout','stderr'})=='UNKNOWN':return [],'UNKNOWN'
    directory=descriptor=None
    try:
        directory=os.open(Path(root)/'logs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);info=os.fstat(directory)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700 or source_log_seal(info)!=source_log_seal(os.lstat(Path(root)/'logs')):return [],'UNKNOWN'
        name=str(ordinal)+'-'+stage+'.'+stream;descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory);before=os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<=before.st_size<=256*1024*1024:return [],'UNKNOWN'
        start=max(0,before.st_size-65536);os.lseek(descriptor,start,os.SEEK_SET)
        with os.fdopen(descriptor,'rb',closefd=False) as handle:raw=handle.read(65537)
        named=os.stat(name,dir_fd=directory,follow_symlinks=False)
        if len(raw)!=before.st_size-start or source_log_seal(before)!=source_log_seal(os.fstat(descriptor)) or source_log_seal(before)!=source_log_seal(named):return [],'UNKNOWN'
        if source_log_seal(info)!=source_log_seal(os.fstat(directory)) or source_log_seal(info)!=source_log_seal(os.lstat(Path(root)/'logs')):return [],'UNKNOWN'
        if start:raw=raw.partition(b'\n')[2]
        return [line for line in raw.split(b'\n')[:-1] if len(line)<=4096],('TAIL' if start else 'FULL')
    except Exception:return [],'UNKNOWN'
    finally:
        if descriptor is not None:os.close(descriptor)
        if directory is not None:os.close(directory)

def source_log_diagnostic(root,stage,ordinal,app,bundle):
    result=source_log_unknown(stage,ordinal);result['binding']='MATCHED_REAPED_FAILED_COMMAND';cache={}
    def bound(key):
        if key not in cache:
            rel,expected,size,origin,contexts=SOURCE_LOG_SOURCES[key]
            cache[key]=source_log_source_bound(Path(app)/rel,key)
            if origin=='bundle':cache[key]=cache[key] and bundle is not None and source_log_source_bound(Path(bundle)/rel,key)
        return cache[key]
    for stream in ('stdout','stderr'):
        lines,scope=source_log_tail(root,ordinal,stage,stream);result[stream+'_scope']=scope
        for line in lines:
            labels=[]
            for label,key,number,kind,text in SOURCE_LOG_ENVELOPES:
                if kind!=('progress' if stream=='stdout' else 'error') or stage not in SOURCE_LOG_SOURCES[key][4]:continue
                if line==text.encode('utf-8') and bound(key) and label not in labels:labels.append(label)
            if len(labels)>1:result['ambiguous']=True
            elif labels:
                label=labels[0]
                if stream=='stdout':result['last_stage']=source_log_label(label,stage,'progress')
                else:
                    result['error']=source_log_label(label,stage,'error')
                    if label not in result['error_labels']:
                        result['error_labels'].append(label)
                        if len(result['error_labels'])>8:result['error_labels'].pop(0);result['errors_truncated']=True
            if stream=='stderr' and stage in ('phase28','phase30'):
                match=re.fullmatch((stage+r' verifier failed at line ([1-9][0-9]{0,3}): [\x20-\x7e]{1,4096}').encode('ascii'),line)
                key=stage.upper()
                if match and int(match[1]) in SOURCE_LOG_TRAP_LINES[key] and bound(key):result['trap']={'label':key+'_ERR_L'+str(int(match[1])).zfill(3)}
    return source_phase_projection(result)

def preflight_projection(value):
    unknown={'error_category':'UNKNOWN','chain':'UNKNOWN'}
    if type(value) is not dict:return unknown
    chain=value.get('chain')
    if type(chain) is not list or not 1<=len(chain)<=6:return unknown
    result=[]
    for row in chain:
        if type(row) is not dict or set(row)!={'function','line'}:return unknown
        name=row.get('function');line=row.get('line')
        if type(name) is not str or name not in PREFLIGHT_SITES or type(line) is not int:return unknown
        low,high=PREFLIGHT_SITES[name]
        if not low<=line<=high:return unknown
        result.append({'function':name,'line':line})
    if result[0]['function']!='source_preflight':return unknown
    return {'error_category':closed(value.get('error_category'),set(PREPARATION_ERRORS.values())),'chain':result}

def preflight_marker_record(stderr,nonce,authkey):
    import hmac
    try:
        if type(nonce) is not str or re.fullmatch('[a-f0-9]{32}',nonce) is None or type(authkey) is not str or SHA.fullmatch(authkey) is None:return None
        if type(stderr) is not str or len(stderr.encode('utf-8'))>65536:return None
        lines=[line[len(PREFLIGHT_PREFIX):] for line in stderr.splitlines() if line.startswith(PREFLIGHT_PREFIX)]
        if len(lines)!=1 or len(lines[0])>4096:return None
        envelope=decoded(lines[0])
        if type(envelope) is not dict or set(envelope)!={'payload','mac'}:return None
        payload=envelope['payload'];mac=envelope['mac']
        if type(payload) is not dict or set(payload)!={'schema','nonce','probe_sha256','error_category','chain'}:return None
        if payload['schema']!='nakpanel-forward-preflight-marker-v1' or payload['nonce']!=nonce or payload['probe_sha256']!=PREFLIGHT_PROBE_SHA:return None
        if type(mac) is not str or SHA.fullmatch(mac) is None:return None
        if not hmac.compare_digest(mac,hmac.new(bytes.fromhex(authkey),canonical(payload),hashlib.sha256).hexdigest()):return None
        observation=preflight_projection(payload)
        if observation['chain']=='UNKNOWN' or payload['error_category'] not in set(PREPARATION_ERRORS.values())|{'UNKNOWN'}:return None
        return envelope
    except Exception:return None

def preflight_marker(stderr,nonce,authkey):
    record=preflight_marker_record(stderr,nonce,authkey)
    return preflight_projection(record['payload'] if record is not None else None)

def preflight_companion(path,nonce,ordinal,authkey):
    unknown=preflight_projection(None)
    try:
        data=diagnostic_bytes(Path(path).parent,Path(path).name,8192)
        if data is None:return unknown
        row=decoded(data)
        if type(row) is not dict or set(row)!={'schema','nonce','command_ordinal','helper_sha256','probe_sha256','matches','guest_returncode','marker'}:return unknown
        if row['schema']!='nakpanel-forward-preflight-companion-v1' or row['nonce']!=nonce or type(row['command_ordinal']) is not int or row['command_ordinal']!=ordinal:return unknown
        if row['helper_sha256']!=PREFLIGHT_HELPER_SHA or row['probe_sha256']!=PREFLIGHT_PROBE_SHA or type(row['matches']) is not int or row['matches']!=1:return unknown
        if type(row['guest_returncode']) is not int or not -255<=row['guest_returncode']<=255 or row['guest_returncode']==0:return unknown
        return preflight_marker(PREFLIGHT_PREFIX+canonical(row['marker']).decode('ascii'),nonce,authkey)
    except Exception:return unknown

def preflight_guest_program(source,nonce,authkey):
    require(type(source) is str and digest(source.encode('utf-8'))==PREFLIGHT_PROBE_SHA,'pinned preparation probe differs')
    require(type(nonce) is str and re.fullmatch('[a-f0-9]{32}',nonce) and type(authkey) is str and SHA.fullmatch(authkey),'invalid preparation observation binding')
    bundle={'source':source,'nonce':nonce,'authkey':authkey,'probe_sha256':PREFLIGHT_PROBE_SHA,'sites':PREFLIGHT_SITES,'errors':PREPARATION_ERRORS,'prefix':PREFLIGHT_PREFIX}
    return 'B='+repr(bundle)+'\n'+GUEST_PREFLIGHT_WRAPPER

# Only source_preflight is wrapped. The exact pinned module is loaded without
# main, then its original main AST runs with the same stdin and arguments.
GUEST_PREFLIGHT_WRAPPER=r"""import ast,hashlib,hmac,json,sys,types
filename='<nakpanel-forward-pinned-probe>'
source=B['source']
if hashlib.sha256(source.encode('utf-8')).hexdigest()!=B['probe_sha256']:raise RuntimeError('pinned probe differs')
tree=ast.parse(source,filename=filename)
compiled=compile(tree,filename,'exec')
namespace={'__name__':'nakpanel_observed_probe','__file__':filename}
exec(compiled,namespace)
trusted={}
def visit(code,label):
    if label in B['sites']:trusted[id(code)]=label
    for item in code.co_consts:
        if isinstance(item,types.CodeType):visit(item,label+'.'+item.co_name)
for item in compiled.co_consts:
    if isinstance(item,types.CodeType) and item.co_name in B['sites']:visit(item,item.co_name)
original=namespace['source_preflight']
def observed(config):
    try:return original(config)
    except Exception as error:
        try:
            chain=[];tb=error.__traceback__;valid=True
            while tb is not None:
                code=tb.tb_frame.f_code
                if code.co_filename==filename:
                    label=trusted.get(id(code));line=tb.tb_lineno
                    if label is None or not B['sites'][label][0]<=line<=B['sites'][label][1]:valid=False;break
                    chain.append({'function':label,'line':line})
                tb=tb.tb_next
            if valid and 1<=len(chain)<=6 and chain[0]['function']=='source_preflight':
                payload={'schema':'nakpanel-forward-preflight-marker-v1','nonce':B['nonce'],'probe_sha256':B['probe_sha256'],'error_category':B['errors'].get(type(error).__name__,'UNKNOWN'),'chain':chain}
                data=(json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
                envelope={'payload':payload,'mac':hmac.new(bytes.fromhex(B['authkey']),data,hashlib.sha256).hexdigest()}
                sys.stderr.write(B['prefix']+json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n');sys.stderr.flush()
        except Exception:pass
        raise
namespace['source_preflight']=observed
namespace['__name__']='__main__'
exec(compile(ast.Module(body=[tree.body[-1]],type_ignores=[]),filename,'exec'),namespace)
"""

def observed_prepare(helper,spec,output,companion,nonce,ordinal,authkey):
    import ast
    helper=Path(helper);probe=helper.with_name('ubuntu-forward-migration-probe.py')
    source=helper.read_bytes();probe_source=probe.read_text()
    require(digest(source)==PREFLIGHT_HELPER_SHA and digest(probe_source.encode('utf-8'))==PREFLIGHT_PROBE_SHA,'pinned preparation source differs')
    require(type(nonce) is str and re.fullmatch('[a-f0-9]{32}',nonce) and type(ordinal) is str and re.fullmatch('[1-9][0-9]{0,5}',ordinal) and type(authkey) is str and SHA.fullmatch(authkey),'invalid preparation observation binding')
    tree=ast.parse(source,filename=str(helper));namespace={'__name__':'nakpanel_observed_fixture','__file__':str(helper)}
    exec(compile(tree,str(helper),'exec'),namespace)
    original_subprocess=namespace['subprocess'];original_run=original_subprocess.run
    observed={'matches':0,'marker':None,'guest_returncode':None}
    def intercepted(*args,**kwargs):
        actual=args;matched=False
        try:
            if len(args)==1 and type(args[0]) is list and len(args[0])==8 and args[0][:2]==['multipass','exec'] and args[0][3:7]==['--','sudo','python3','-c'] and args[0][7]==probe_source and set(kwargs)=={'input','text','capture_output','env','timeout'} and kwargs['text'] is True and kwargs['capture_output'] is True and kwargs['env'] is None and kwargs['timeout']==3600 and type(kwargs['input']) is str and len(kwargs['input'].encode('utf-8'))<=65536:
                request=decoded(kwargs['input'])
                if type(request) is dict and set(request)=={'action','config'} and request['action']=='source-preflight' and type(request['config']) is dict and request['config'].get('source_vm')==args[0][2]:
                    matched=True;observed['matches']+=1
                    command=list(args[0]);command[7]=preflight_guest_program(probe_source,nonce,authkey);actual=(command,)
        except Exception:pass
        result=original_run(*actual,**kwargs)
        if matched and observed['matches']==1:
            try:
                if type(result.returncode) is int and result.returncode!=0:
                    observed['marker']=preflight_marker_record(result.stderr,nonce,authkey);observed['guest_returncode']=result.returncode
            except Exception:pass
        return result
    class SubprocessObserver:
        def __getattr__(self,name):return intercepted if name=='run' else getattr(original_subprocess,name)
    namespace['subprocess']=SubprocessObserver();previous=sys.argv
    try:
        sys.argv=[str(helper),'--prepare',str(spec),str(output)];namespace['__name__']='__main__'
        exec(compile(ast.Module(body=[tree.body[-1]],type_ignores=[]),str(helper),'exec'),namespace)
    finally:
        sys.argv=previous
        try:
            if observed['matches']==1 and observed['marker'] is not None:
                publish(companion,{'schema':'nakpanel-forward-preflight-companion-v1','nonce':nonce,'command_ordinal':int(ordinal),'helper_sha256':PREFLIGHT_HELPER_SHA,'probe_sha256':PREFLIGHT_PROBE_SHA,**observed})
        except Exception:pass

def qualifier_blob(path,expected,size):
    path=Path(path)
    require(path.is_absolute() and path.parent.resolve()==path.parent,'qualifier path alias')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and not before.st_mode&0o022 and before.st_nlink==1 and before.st_size==size,'qualifier blob metadata differs')
        with os.fdopen(descriptor,'rb',closefd=False) as stream:data=stream.read(size+1)
        after=os.fstat(descriptor);current=path.lstat()
        signature=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(signature(before)==signature(after)==signature(current) and len(data)==size and digest(data)==expected,'qualifier blob identity differs')
        return data
    finally:os.close(descriptor)

def qualifier_artifacts(controller,app):
    import difflib
    controller,app=Path(controller),Path(app)
    require(controller.is_absolute() and app.is_absolute() and controller.resolve()==controller and app.resolve()==app and controller!=app and controller not in app.parents and app not in controller.parents,'qualifier/source paths overlap or alias')
    blobs={name:qualifier_blob(controller/name,h,size) for name,(h,size) in QUALIFIER_FILES.items()}
    for name,expected in QUALIFIER_GIT_BLOBS.items():
        data=blobs[name];require(hashlib.sha1(b'blob '+str(len(data)).encode('ascii')+b'\0'+data).hexdigest()==expected,'delivered qualifier Git blob differs')
    old_probe=qualifier_blob(app/'deploy/multipass/ubuntu-forward-migration-probe.py',PREFLIGHT_PROBE_SHA,67875)
    old_tests=qualifier_blob(app/'deploy/multipass/ubuntu_forward_migration_fixture_test.py',QUALIFIER_IDENTITY['original_test_sha256'],71105)
    def change(old,new,name):return ''.join(difflib.unified_diff(old.decode('utf-8').splitlines(keepends=True),new.decode('utf-8').splitlines(keepends=True),fromfile='a/'+name,tofile='b/'+name)).encode('utf-8')
    probe_patch=change(old_probe,blobs['qualifier-probe.py'],'deploy/multipass/ubuntu-forward-migration-probe.py')
    require(digest(probe_patch)=='e9993e0216525cc4b08300327523f97cf9c591ea17e78b733600d57fc2f99c6a','approved qualifier code diff differs')
    delivery=probe_patch+change(old_tests,blobs['qualifier-tests.py'],'deploy/multipass/ubuntu_forward_migration_fixture_test.py')
    require(delivery==blobs['qualifier-delivery.patch'],'exact two-blob delivery diff differs')
    return {'source':blobs['qualifier-probe.py'].decode('utf-8'),'identity':dict(QUALIFIER_IDENTITY)}

def qualifier_binding(nonce,ordinal,action,invocation,config):
    require(type(config) is dict and type(config.get('source_vm')) is str and type(config.get('run_token')) is str,'qualifier private binding missing')
    value={'nonce':nonce,'command_ordinal':ordinal,'action':action,'invocation':invocation,'vm_sha256':digest(config['source_vm'].encode('utf-8')),'token_sha256':digest(config['run_token'].encode('utf-8')),'config_sha256':digest(canonical(config))}
    require(qualifier_binding_valid(value),'qualifier invocation binding differs')
    return value

def qualifier_binding_valid(value):
    if type(value) is not dict or set(value)!={'nonce','command_ordinal','action','invocation','vm_sha256','token_sha256','config_sha256'}:return False
    if type(value['nonce']) is not str or re.fullmatch('[a-f0-9]{32}',value['nonce']) is None:return False
    if type(value['command_ordinal']) is not int or not 0<value['command_ordinal']<=100000:return False
    if type(value['action']) is not str or value['action'] not in QUALIFIER_ACTIONS:return False
    if type(value['invocation']) is not int or value['invocation']!=QUALIFIER_ACTIONS[value['action']][1]:return False
    return all(type(value[k]) is str and SHA.fullmatch(value[k]) for k in ('vm_sha256','token_sha256','config_sha256'))

def qualifier_projection(value):
    unknown={'action':'UNKNOWN','probe_sha256':'UNKNOWN','error_category':'UNKNOWN','chain':'UNKNOWN'}
    if type(value) is not dict or type(value.get('action')) is not str or value['action'] not in QUALIFIER_ACTIONS or value.get('probe_sha256')!=QUALIFIER_PROBE_SHA:return unknown
    chain=value.get('chain');result=[]
    if type(chain) is not list or not 1<=len(chain)<=6:return unknown
    for row in chain:
        if type(row) is not dict or set(row)!={'function','line'}:return unknown
        name=row['function'];line=row['line']
        if type(name) is not str or name not in QUALIFIER_SITES or type(line) is not int or not QUALIFIER_SITES[name][0]<=line<=QUALIFIER_SITES[name][1]:return unknown
        result.append({'function':name,'line':line})
    if result[0]['function']!=QUALIFIER_ACTIONS[value['action']][0]:return unknown
    return {'action':value['action'],'probe_sha256':QUALIFIER_PROBE_SHA,'error_category':closed(value.get('error_category'),set(PREPARATION_ERRORS.values())),'chain':result}

def qualifier_marker_record(stderr,binding,authkey):
    import hmac
    try:
        if not qualifier_binding_valid(binding) or type(authkey) is not str or SHA.fullmatch(authkey) is None:return None
        if type(stderr) is not str or len(stderr.encode('utf-8'))>65536:return None
        lines=[x[len(QUALIFIER_PREFIX):] for x in stderr.splitlines() if x.startswith(QUALIFIER_PREFIX)]
        if len(lines)!=1 or len(lines[0])>4096:return None
        row=decoded(lines[0])
        if type(row) is not dict or set(row)!={'payload','mac'}:return None
        payload=row['payload']
        if type(payload) is not dict or set(payload)!={'schema','binding','probe_sha256','error_category','chain'} or payload['schema']!='nakpanel-forward-qualifier-marker-v1' or not qualifier_binding_valid(payload['binding']) or payload['binding']!=binding:return None
        if type(row['mac']) is not str or SHA.fullmatch(row['mac']) is None or not hmac.compare_digest(row['mac'],hmac.new(bytes.fromhex(authkey),canonical(payload),hashlib.sha256).hexdigest()):return None
        observation=qualifier_projection(dict(payload,action=binding['action']))
        if observation['chain']=='UNKNOWN' or payload['error_category'] not in set(PREPARATION_ERRORS.values())|{'UNKNOWN'}:return None
        return row
    except Exception:return None

def qualifier_companion(path,nonce,ordinal,authkey,vm,token):
    unknown=qualifier_projection(None)
    try:
        data=diagnostic_bytes(Path(path).parent,Path(path).name,8192)
        if data is None:return unknown
        row=decoded(data)
        if type(row) is not dict or set(row)!={'schema','helper_sha256','original_probe_sha256','qualifier_probe_sha256','matches','guest_returncode','marker'} or row['schema']!='nakpanel-forward-qualifier-companion-v1':return unknown
        if row['helper_sha256']!=PREFLIGHT_HELPER_SHA or row['original_probe_sha256']!=PREFLIGHT_PROBE_SHA or row['qualifier_probe_sha256']!=QUALIFIER_PROBE_SHA:return unknown
        binding=row['marker']['payload']['binding']
        if not qualifier_binding_valid(binding) or binding['nonce']!=nonce or type(ordinal) is not int or binding['command_ordinal']!=ordinal:return unknown
        if binding['vm_sha256']!=digest(vm.encode('utf-8')) or binding['token_sha256']!=digest(token.encode('utf-8')):return unknown
        if type(row['matches']) is not int or row['matches']!=binding['invocation'] or type(row['guest_returncode']) is not int or not -255<=row['guest_returncode']<=255 or row['guest_returncode']==0:return unknown
        marker=qualifier_marker_record(QUALIFIER_PREFIX+canonical(row['marker']).decode('ascii'),binding,authkey)
        return qualifier_projection(dict(marker['payload'],action=binding['action'])) if marker else unknown
    except Exception:return unknown

def qualifier_guest_program(source,binding,authkey):
    require(type(source) is str and digest(source.encode('utf-8'))==QUALIFIER_PROBE_SHA,'reviewed qualifier probe differs')
    require(qualifier_binding_valid(binding) and type(authkey) is str and SHA.fullmatch(authkey),'qualifier observation binding differs')
    bundle={'source':source,'binding':binding,'authkey':authkey,'probe_sha256':QUALIFIER_PROBE_SHA,'sites':QUALIFIER_SITES,'errors':PREPARATION_ERRORS,'prefix':QUALIFIER_PREFIX,'root':QUALIFIER_ACTIONS[binding['action']][0]}
    return 'B='+repr(bundle)+'\n'+GUEST_QUALIFIER_WRAPPER

GUEST_QUALIFIER_WRAPPER=r"""import ast,hashlib,hmac,json,sys,types
filename='<nakpanel-forward-reviewed-qualifier>'
source=B['source']
if hashlib.sha256(source.encode('utf-8')).hexdigest()!=B['probe_sha256']:raise RuntimeError('qualifier source differs')
tree=ast.parse(source,filename=filename);compiled=compile(tree,filename,'exec')
namespace={'__name__':'nakpanel_qualifier_probe','__file__':filename}
exec(compiled,namespace)
trusted={}
def visit(code,label):
    if label in B['sites']:trusted[id(code)]=label
    for item in code.co_consts:
        if isinstance(item,types.CodeType):visit(item,label+'.'+item.co_name)
for item in compiled.co_consts:
    if isinstance(item,types.CodeType):visit(item,item.co_name)
original=namespace[B['root']]
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
def observed(config):
    binding=B['binding']
    if type(config) is not dict or hashlib.sha256(canonical(config)).hexdigest()!=binding['config_sha256'] or hashlib.sha256(config.get('source_vm','').encode('utf-8')).hexdigest()!=binding['vm_sha256'] or hashlib.sha256(config.get('run_token','').encode('utf-8')).hexdigest()!=binding['token_sha256']:raise RuntimeError('qualifier private binding differs')
    try:return original(config)
    except Exception as error:
        try:
            chain=[];tb=error.__traceback__;valid=True
            while tb is not None:
                code=tb.tb_frame.f_code
                if code.co_filename==filename:
                    label=trusted.get(id(code));line=tb.tb_lineno
                    if label is None or not B['sites'][label][0]<=line<=B['sites'][label][1]:valid=False;break
                    chain.append({'function':label,'line':line})
                tb=tb.tb_next
            if valid and 1<=len(chain)<=6 and chain[0]['function']==B['root']:
                payload={'schema':'nakpanel-forward-qualifier-marker-v1','binding':binding,'probe_sha256':B['probe_sha256'],'error_category':B['errors'].get(type(error).__name__,'UNKNOWN'),'chain':chain}
                envelope={'payload':payload,'mac':hmac.new(bytes.fromhex(B['authkey']),canonical(payload),hashlib.sha256).hexdigest()}
                sys.stderr.write(B['prefix']+json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n');sys.stderr.flush()
        except Exception:pass
        raise
namespace[B['root']]=observed
namespace['__name__']='__main__'
exec(compile(ast.Module(body=[tree.body[-1]],type_ignores=[]),filename,'exec'),namespace)
"""

def qualifier_invocation(args,kwargs,original,vm,token):
    try:
        if len(args)!=1 or type(args[0]) is not list or len(args[0])!=8 or args[0][:3]!=['multipass','exec',vm] or args[0][3:7]!=['--','sudo','python3','-c'] or args[0][7]!=original:return None
        if set(kwargs)!={'input','text','capture_output','env','timeout'} or kwargs['text'] is not True or kwargs['capture_output'] is not True or kwargs['env'] is not None or type(kwargs['timeout']) is not int or kwargs['timeout']!=3600:return None
        if type(kwargs['input']) is not str or len(kwargs['input'].encode('utf-8'))>65536:return None
        request=decoded(kwargs['input'])
        if type(request) is not dict or set(request)!={'action','config'} or type(request['action']) is not str or request['action'] not in QUALIFIER_ACTIONS or type(request['config']) is not dict:return None
        if request['config'].get('source_vm')!=vm or request['config'].get('run_token')!=token or json.dumps(request)!=kwargs['input']:return None
        return request
    except Exception:return None

def observed_qualifier_prepare(helper,spec,output,companion,nonce,ordinal,authkey,controller,owned_vm,token):
    import ast
    helper=Path(helper)
    require(helper.is_absolute() and helper.resolve()==helper,'preparation helper path alias')
    app=helper.parent.parent.parent
    verified=qualifier_artifacts(Path(controller),app)
    source=qualifier_blob(helper,PREFLIGHT_HELPER_SHA,30836)
    probe_source=qualifier_blob(helper.with_name('ubuntu-forward-migration-probe.py'),PREFLIGHT_PROBE_SHA,67875).decode('utf-8')
    spec=regular(spec,True);require(spec.is_absolute() and spec.parent.stat().st_uid==os.getuid() and not spec.parent.stat().st_mode&0o077 and spec.stat().st_nlink==1 and spec.stat().st_size<=65536,'private preparation spec alias or size')
    config=decoded(spec.read_bytes())
    require(type(config) is dict and config.get('source_vm')==owned_vm and config.get('run_token')==token and type(owned_vm) is str and re.fullmatch('nakpanel-[A-Za-z0-9-]{1,120}',owned_vm) and type(token) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{5,63}',token),'owned preparation source binding differs')
    require(type(ordinal) is str and re.fullmatch('[1-9][0-9]{0,5}',ordinal),'preparation ordinal differs')
    qualifier_binding(nonce,int(ordinal),'source-preflight',1,config)
    require(type(authkey) is str and SHA.fullmatch(authkey),'preparation HMAC key differs')
    tree=ast.parse(source,filename=str(helper));namespace={'__name__':'nakpanel_qualifier_fixture','__file__':str(helper)}
    exec(compile(tree,str(helper),'exec'),namespace)
    original_subprocess=namespace['subprocess'];original_run=original_subprocess.run
    observed={'matches':0,'guest_returncode':None,'marker':None}
    def intercepted(*args,**kwargs):
        actual=args;request=qualifier_invocation(args,kwargs,probe_source,owned_vm,token);binding=None
        if request is not None:
            invocation=QUALIFIER_ACTIONS[request['action']][1]
            require(invocation==observed['matches']+1,'qualifier invocation sequence differs')
            observed['matches']=invocation
            binding=qualifier_binding(nonce,int(ordinal),request['action'],invocation,request['config'])
            command=list(args[0]);command[7]=qualifier_guest_program(verified['source'],binding,authkey);actual=(command,)
        result=original_run(*actual,**kwargs)
        if binding is not None and type(result.returncode) is int and result.returncode!=0:
            observed['marker']=qualifier_marker_record(result.stderr,binding,authkey);observed['guest_returncode']=result.returncode
        return result
    class SubprocessObserver:
        def __getattr__(self,name):return intercepted if name=='run' else getattr(original_subprocess,name)
    namespace['subprocess']=SubprocessObserver();previous=sys.argv
    try:
        sys.argv=[str(helper),'--prepare',str(spec),str(output)];namespace['__name__']='__main__'
        exec(compile(ast.Module(body=[tree.body[-1]],type_ignores=[]),str(helper),'exec'),namespace)
    finally:
        sys.argv=previous
        try:
            if observed['marker'] is not None:
                publish(companion,{'schema':'nakpanel-forward-qualifier-companion-v1','helper_sha256':PREFLIGHT_HELPER_SHA,'original_probe_sha256':PREFLIGHT_PROBE_SHA,'qualifier_probe_sha256':QUALIFIER_PROBE_SHA,**observed})
        except Exception:pass

def preparation_projection(value):
    unknown={'stage':'UNKNOWN','status':'UNKNOWN','error_category':'UNKNOWN'}
    if type(value) is not dict:return unknown
    stage=closed(value.get('stage'),PREPARATION_STAGES|set(PREPARATION_EARLY.values()));status=closed(value.get('status'),{'running','passed','failed'})
    if stage=='UNKNOWN' or status=='UNKNOWN':return unknown
    result={'stage':stage,'status':status,'error_category':closed(value.get('error_category'),set(PREPARATION_ERRORS.values())) if status=='failed' else 'UNKNOWN'}
    if stage=='EARLY_SOURCE_PREFLIGHT_COMMAND':result['source_preflight']=preflight_projection(value.get('source_preflight'))
    if type(value.get('qualifier_probe')) is dict:result['qualifier_probe']=qualifier_projection(value['qualifier_probe'])
    return result

def diagnostic_bytes(parent,name,limit):
    # Private local data only; never follow links, block on special files, or
    # read an unbounded inventory/stream. Metadata is checked on open handles.
    directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        d=os.fstat(directory)
        if not stat.S_ISDIR(d.st_mode) or d.st_uid!=os.getuid() or d.st_mode&0o077:return None
        descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            info=os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_nlink!=1 or not 0<info.st_size<=limit:return None
            with os.fdopen(descriptor,'rb',closefd=False) as stream:data=stream.read(limit+1)
            return data if len(data)==info.st_size and len(data)<=limit else None
        finally:os.close(descriptor)
    finally:os.close(directory)

def preparation_diagnostic(prepared,stderr=None):
    unknown=preparation_projection(None)
    try:
        try:Path(prepared).lstat()
        except FileNotFoundError:
            if stderr is None:return unknown
            data=diagnostic_bytes(Path(stderr).parent,Path(stderr).name,128)
            stage=PREPARATION_EARLY.get(data)
            return {'stage':stage,'status':'failed','error_category':'runtime'} if stage else unknown
        data=diagnostic_bytes(prepared,'preparation-receipt.json',65536)
        if data is None:return unknown
        row=decoded(data)
        if type(row) is not dict or type(row.get('version')) is not int or row['version']!=1 or closed(row.get('stage'),PREPARATION_STAGES)=='UNKNOWN':return unknown
        error=row.get('error_type')
        if row.get('status')=='failed' and (type(error) is not str or not error):return unknown
        category=PREPARATION_ERRORS.get(error,'UNKNOWN') if type(error) is str else 'UNKNOWN'
        return preparation_projection({'stage':row.get('stage'),'status':row.get('status'),'error_category':category})
    except Exception:return unknown

def proof_projection(value):
    if type(value) is not dict:return None
    n=value.get('invocation')
    if type(n) is not int or not 0<n<=65535:return None
    r={'invocation':n,'context':closed(value.get('context'),PROOF_CONTEXTS),'active':value.get('active') is True,'json_decoded':value.get('json_decoded') is True,'checks':{}}
    checks=value.get('checks')
    if type(checks) is dict:r['checks']={k:checks[k] for k in CHECK_KEYS if type(checks.get(k)) is bool}
    return r

def failure_projection(value):
    value=value if type(value) is dict else {}
    count=value.get('command_count');r={'boundary':closed(value.get('boundary'),BOUNDARIES),'predicate':closed(value.get('predicate'),PREDICATES),'kind':closed(value.get('kind'),{'semantic','command','cancelled','deadline'}),'command_count':count if type(count) is int and 0<=count<=100000 else 0}
    if type(value.get('source_phase_diagnostic')) is dict:r['source_phase_diagnostic']=source_phase_projection(value['source_phase_diagnostic'])
    if type(value.get('preparation_diagnostic')) is dict:r['preparation_diagnostic']=preparation_projection(value['preparation_diagnostic'])
    observation=proof_projection(value.get('proof_observation'))
    if observation is not None:r['proof_observation']=observation
    return r

def outcomes_projection(state):
    primary=state.get('primary_outcome');primary=primary if type(primary) is dict else {}
    work=dict(status=primary.get('status') if primary.get('status') in ('not_run','passed','failed') else 'not_run',**failure_projection(primary))
    cleanup=state.get('cleanup_outcome');cleanup=cleanup if type(cleanup) is dict else {}
    result={'status':cleanup.get('status') if cleanup.get('status') in ('not_run','passed','failed') else 'not_run','failures':[]}
    rows=cleanup.get('failures')
    if type(rows) is list:
        for row in rows[:4]:
            if type(row) is dict:result['failures'].append(dict(role=closed(row.get('role'),{'source','negative','positive','private_staging'}),**failure_projection(row)))
    return work,result

class PredicateRefusal(Refusal):
    def __init__(self,predicate):
        self.predicate=predicate if predicate in PREDICATES else 'UNKNOWN'
        super().__init__('fixed forward predicate failed')
def predicate_require(ok,predicate):
    if not ok:raise PredicateRefusal(predicate)

def require(ok,message):
    if not ok:raise Refusal(message)
def utc():return datetime.now(timezone.utc).isoformat()
def instant(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)',value),'invalid UTC time')
    parsed=value.replace('Z','+00:00');fraction=re.search(r'\.(\d{1,6})(?=\+00:00$)',parsed)
    if fraction:parsed=parsed[:fraction.start(1)]+fraction.group(1).ljust(6,'0')+parsed[fraction.end(1):]
    try:return datetime.fromisoformat(parsed)
    except ValueError:raise Refusal('invalid UTC time')
def digest(data):return hashlib.sha256(data).hexdigest()
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
def duplicate_pairs(pairs):
    result={}
    for k,v in pairs:
        require(k not in result,'duplicate JSON field');result[k]=v
    return result
def decoded(data):
    try:return json.loads(data,object_pairs_hook=duplicate_pairs)
    except (ValueError,UnicodeError):raise Refusal('invalid JSON data')
def regular(path,private=False):
    p=Path(path);s=p.lstat();predicate_require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid(),'trusted_file_metadata')
    predicate_require(not s.st_mode&0o022,'trusted_file_metadata')
    if private:predicate_require(not s.st_mode&0o077,'trusted_file_metadata')
    return p

def publish(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        d=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        try:os.unlink(name)
        except FileNotFoundError:pass

def read_admission(path,expected_sha,now=None):
    p=regular(path,True);require(p.stat().st_size<=262144,'admission exceeds data-only bound');require(SHA.fullmatch(expected_sha or '') and sha(p)==expected_sha,'out-of-band admission SHA differs')
    a=decoded(p.read_bytes());require(type(a) is dict and a.get('state')=='AUTHORIZED','hosted admission is PENDING')
    keys={'schema','state','source_commit','source_tree','controller_commit','valid_from','expires_at','nonce','repository','baseline_reviews','artifact','payload','oci_image_ref','authority','controller_files','app_helpers','qualifier'}
    require(set(a)==keys and a['schema']=='nakpanel-hosted-forward-admission-v1','admission schema/fields differ')
    require(a['source_commit']==COMMIT and a['source_tree']==TREE and re.fullmatch('[a-f0-9]{40}',a['controller_commit'] or ''),'source/controller commit differs')
    now=now or datetime.now(timezone.utc);start,end=instant(a['valid_from']),instant(a['expires_at'])
    require(start<=now<end and 0<(end-start).total_seconds()<=24*3600,'admission expired or not yet valid')
    require(re.fullmatch('[a-f0-9]{32}',a['nonce'] or '') and a['repository']=='Smartqix/nakpanel','unsafe run/repository identity')
    require(a['baseline_reviews']==ROOT_BASELINES,'accepted application baseline bindings differ')
    require(type(a['authority']) is dict and type(a['authority'].get('maximum_guests')) is int and type(a['authority'].get('cpus')) is int and a['authority'].get('production') is False and a['authority']=={'scope':'fresh-synthetic-native-forward-only','maximum_guests':2,'cpus':2,'memory':'5G','disk':'32G','production':False},'unsupported authority scope/resources')
    require(re.fullmatch('docker.io/library/nginx@sha256:[a-f0-9]{64}',a['oci_image_ref'] or ''),'immutable official OCI reference missing')
    ar=a['artifact'];require(type(ar) is dict and set(ar)=={'id','run_id','name','size','sha256','expires_at'},'artifact schema differs')
    require(all(type(ar[k]) is int and 0<ar[k]<=2**40 for k in ('id','run_id','size')) and ar['size']<=2**30 and SHA.fullmatch(ar['sha256'] or '') and type(ar['name']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,150}',ar['name']),'artifact binding invalid')
    require(now<instant(ar['expires_at']),'selected artifact expired')
    pld=a['payload'];require(type(pld) is dict and set(pld)=={'archive','archive_size','archive_sha256','manifest_sha256','public_key_sha256','binaries'},'payload schema differs')
    require(pld['archive']=='candidate/nakpanel-29.0.0-linux-amd64.tar.gz' and type(pld['archive_size']) is int and 0<pld['archive_size']<=2**30,'payload archive differs')
    require(all(type(pld[k]) is str and SHA.fullmatch(pld[k]) for k in ('archive_sha256','manifest_sha256','public_key_sha256')),'payload digests missing')
    require(type(pld['binaries']) is dict and set(pld['binaries'])==set(BINARY_PATHS) and all(type(v) is str and SHA.fullmatch(v) for v in pld['binaries'].values()),'binary inventory differs')
    require(all(pld[k]==v for k,v in ACCEPTED_PAYLOAD.items()),'selected payload differs from accepted native application bytes')
    for key in ('controller_files','app_helpers'):
        require(type(a[key]) is dict and a[key] and all(safe_name(n) and type(h) is str and SHA.fullmatch(h) for n,h in a[key].items()),'helper inventory missing/unsafe')
    require('forward_hosted.py' in a['controller_files'] and 'deploy/multipass/common.sh' in a['app_helpers'],'required coordinator/helpers missing')
    require(a['qualifier']==QUALIFIER_IDENTITY,'explicit runtime26/qualifier identity differs')
    require(len(a['app_helpers'])==175 and digest(canonical(a['app_helpers']))==ORIGINAL_HELPERS_SHA,'original source26 helper inventory differs')
    require(all(a['controller_files'].get(name)==value[0] for name,value in QUALIFIER_FILES.items()),'independent C-pinned qualifier artifacts missing')
    return a

def safe_name(name):
    return type(name) is str and bool(name) and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts and str(PurePosixPath(name))==name and '\\' not in name and not any(c in name for c in '\r\n\0')
def check_artifact(row,a,now=None):
    ar=a['artifact'];now=now or datetime.now(timezone.utc)
    require(type(row) is dict and type(row.get('id')) is int and row['id']==ar['id'] and row.get('name')==ar['name'],'artifact API identity differs')
    require(type(row.get('size_in_bytes')) is int and row['size_in_bytes']==ar['size'] and row.get('digest')=='sha256:'+ar['sha256'],'artifact API size/digest differs')
    require(row.get('expired') is False and row.get('expires_at')==ar['expires_at'] and now<instant(row['expires_at']),'artifact expired')
    w=row.get('workflow_run');require(type(w) is dict and type(w.get('id')) is int and w['id']==ar['run_id'] and w.get('head_sha')==COMMIT,'artifact original workflow/source differs')
def check_capacity(row):
    require(type(row) is dict and row.get('status')=='PASS' and row.get('architecture') in ('x86_64','amd64'),'host preflight failed')
    for key,minimum in [('cpu_count',4),('total_memory',14*2**30),('available_memory',11*2**30),('free_disk',80*2**30)]:require(type(row.get(key)) is int and row[key]>=minimum,'host capacity insufficient: '+key)
    require(row.get('kvm_api')==12 and type(row['kvm_api']) is int,'KVM creation not proven')
def check_owner(path,release,token):predicate_require(regular(path,True).read_text()==release+'\tamd64\t'+token+'\n','host_owner_binding')
def check_negative(code,text,required):
    require(type(code) is int and code!=0,'negative check unexpectedly succeeded')
    expected={f'panelctl: target lacks required hosted PHP {v}; tenant intent cannot be rewritten' for v in required if v!='8.5' and re.fullmatch(r'8\.[234]',v)}
    clean=text.strip()
    require(clean in expected,'negative failed for an unrelated reason')
    return next(v for v in required if clean==f'panelctl: target lacks required hosted PHP {v}; tenant intent cannot be rewritten')
def check_pins(pins):
    for name,h in pins.items():predicate_require(sha(regular(name))==h,'input_pin_mismatch')

def extract_zip(path,target):
    require(not Path(target).exists(),'ZIP target already exists');entries=[];seen=set();total=0
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            name=i.filename.rstrip('/') if i.is_dir() else i.filename
            require(safe_name(name) and name not in seen,'unsafe/duplicate ZIP member');seen.add(name)
            kind=(i.external_attr>>16)&0o170000
            require(kind in (0,stat.S_IFREG,stat.S_IFDIR) and not i.flag_bits&1,'nonregular/encrypted ZIP member')
            total+=i.file_size;require(total<=2**31 and len(seen)<=2000,'ZIP expansion exceeds bound');entries.append(i)
        Path(target).mkdir(mode=0o700)
        for i in entries:
            p=Path(target)/i.filename
            if i.is_dir():p.mkdir(mode=0o700,parents=True,exist_ok=True)
            else:
                p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with z.open(i) as src,p.open('xb') as dst:
                    while True:
                        b=src.read(2**20)
                        if not b:break
                        dst.write(b)
                p.chmod(0o600)

def extract_tar(path,target):
    require(not Path(target).exists(),'tar target already exists');seen=set();total=0
    Path(target).mkdir(mode=0o700)
    # Stream bounded members; never collect an unbounded getmembers() list.
    with tarfile.open(path,'r|gz') as t:
        for i in t:
            name=i.name.rstrip('/') if i.isdir() else i.name
            require(safe_name(name) and name not in seen and (i.isdir() or i.isfile()),'unsafe/duplicate/nonregular tar member');seen.add(name);total+=i.size
            require(total<=2**31 and len(seen)<=2000,'tar expansion exceeds bound')
            p=Path(target)/i.name
            if i.isdir():p.mkdir(mode=0o700,parents=True,exist_ok=True)
            else:
                p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with t.extractfile(i) as src,p.open('xb') as dst:
                    while True:
                        block=src.read(2**20)
                        if not block:break
                        dst.write(block)
                p.chmod(0o700 if i.mode&0o111 else 0o600)

def check_paths(app,controller,private,public,runner_temp):
    app,controller,private,public,runner_temp=map(Path,(app,controller,private,public,runner_temp))
    require(app.is_absolute() and controller.is_absolute() and app.resolve()==app and controller.resolve()==controller,'source checkout path is not canonical')
    require(app!=controller and app not in controller.parents and controller not in app.parents,'application/controller checkouts overlap')
    require(private.is_absolute() and public.is_absolute() and private!=public and private.parent.resolve()==runner_temp.resolve() and public.parent.resolve()==runner_temp.resolve(),'private/public roots must be distinct direct children of runner temp')
    require(private not in app.parents and public not in app.parents and app not in private.parents and app not in public.parents and controller not in private.parents and controller not in public.parents,'outputs overlap trusted sources')

def check_positive(pre,result):
    predicate_require(type(pre) is dict and pre.get('compatible') is True and pre.get('mode')=='forward-migration' and pre.get('migration_qualified') is False,'positive_preflight')
    manifest=pre.get('manifest');predicate_require(type(manifest) is dict and manifest.get('format_version')==2 and manifest.get('roundcube_sqlite_path') in ('/var/lib/roundcube/roundcube.sqlite','/var/lib/roundcube/db/roundcube','/var/lib/dbconfig-common/sqlite3/roundcube/roundcube'),'positive_snapshot')
    predicate_require(manifest.get('include_mail_data') is True,'positive_mail_data')
    p=manifest.get('platform');predicate_require(type(p) is dict and p.get('profile')=='ubuntu-24.04' and p.get('version_id')=='24.04' and p.get('architecture')=='amd64' and p.get('internal_php_version')=='8.3' and p.get('php_inventory_complete') is True and p.get('required_php_versions')==['8.5'],'positive_php_inventory')
    predicate_require(type(result) is dict and result.get('schema_mismatch') is False,'positive_restore_result')
    r=result.get('summary');predicate_require(type(r) is dict and r.get('manifest')==manifest and r.get('schema_mismatch') is False and type(r.get('extracted_entries')) is int and r['extracted_entries']>0,'positive_restore_manifest')
    predicate_require(type(r.get('mariadb_restored')) is list and 'np_forward_fixture' in r['mariadb_restored'],'positive_database_import')
    predicate_require(type(r.get('services_started')) is list and r['services_started'] and result.get('services_started')==r['services_started'],'positive_services')

class Budget:
    def __init__(self,start=None,clock=time.monotonic):self.clock=clock;self.start=clock() if start is None else start;self.ends={}
    def allowance(self,stage):
        require(stage in CAPS,'unknown bounded stage');now=self.clock();reserve=0 if stage=='cleanup' else CAPS['cleanup']
        self.ends.setdefault(stage,now+CAPS[stage]);remaining=min(self.ends[stage]-now,self.start+TOTAL_SECONDS-now-reserve)
        if remaining<6:raise Deadline('insufficient stage/cleanup deadline headroom')
        return remaining-4
    def check(self,stage):
        now=self.clock();reserve=0 if stage=='cleanup' else CAPS['cleanup']
        if now>=self.start+TOTAL_SECONDS-reserve:raise Deadline('overall/cleanup deadline expired')
        if stage in self.ends and now>=self.ends[stage]:raise Deadline('cumulative stage deadline expired')


def group_exists(group):
    try:os.killpg(group,0);return True
    except ProcessLookupError:return False
    except PermissionError:return True

# Reviewed v6 group primitive; only the accepted fixed stage-name set is adapted.
class ControlledTermination(KeyboardInterrupt):
 def __init__(self,message,signum=None):
  super().__init__(message);self.signum=signum
def _terminate(signum,frame):raise ControlledTermination('controlled SIGTERM',signum)

def owned_group_wait(group,child,grace):
 deadline=time.monotonic()+grace
 while True:
  child.poll()  # Reap our direct leader before deciding whether its group remains.
  if not group_exists(group):return True
  if time.monotonic()>=deadline:return False
  time.sleep(.01)

def owned_action(B,root,state,command,environment,*,stdout=None,stderr=None,timeout=10800,term_grace=1,kill_grace=2):
 require(state['operation'] in CAPS,'unsupported owned action')
 require(all(type(v) in (int,float) and v>0 for v in (timeout,term_grace,kill_grace)),'owned action needs bounded positive deadlines')
 root=Path(root);folder=root/'actions';folder.mkdir(mode=0o700,exist_ok=True)
 path=folder/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'-'+state['operation']+'.json')
 child=None;phase='starting';received=None;failure=None;timed_out=False;unexpected=False;drained=False;cleanup_error=None;started=utc();previous={};outcome=None
 state['action_tree']={'started':False,'owned_group_empty':False,'leader_reaped':False}
 def terminate(signum,frame):
  nonlocal received
  if received is None:received=signum
  # Acquire the actual newly created PID before unwinding startup. Repeated
  # cancellation while cleaning cannot interrupt custody or receipt publication.
  if phase=='waiting':raise ControlledTermination('controlled owned-action cancellation',signum)
 def publish_terminal_cancellation(error):
  nonlocal outcome
  if outcome is None:return
  # Block real cancellation during durable FAIL publication and restoration.
  # On unmask, an already pending signal may raise through the restored outer
  # handler; the original cancellation is still propagated after FAIL exists.
  blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
  try:
   outcome.update(status='failed',interrupted=True,termination_signal=received if received is not None else getattr(error,'signum',None),error_type=type(error).__name__,finished_at=utc())
   state['action_tree']=outcome;publish(path,outcome);state['action_receipt']=file_ref(path)
  finally:
   try:
    for signum,handler in previous.items():signal.signal(signum,handler)
   finally:
    try:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
    except KeyboardInterrupt:pass
 try:
  try:
   for signum in (signal.SIGINT,signal.SIGTERM):previous[signum]=signal.signal(signum,terminate)
   try:
    child=subprocess.Popen(command,env=environment,stdout=stdout,stderr=stderr,start_new_session=True)
    state['action_tree']['started']=True;phase='waiting'
    if received is not None:raise ControlledTermination('controlled startup cancellation',received)
    child.wait(timeout=timeout)
   except subprocess.TimeoutExpired as error:timed_out=True;failure=error
   except BaseException as error:failure=error
   finally:
    phase='cleanup'
    if child is None:drained=True
    else:
     try:
      if child.returncode==0 and failure is None and received is None:unexpected=not owned_group_wait(child.pid,child,.3)
      if group_exists(child.pid):
       try:os.killpg(child.pid,signal.SIGTERM)
       except ProcessLookupError:pass
       drained=owned_group_wait(child.pid,child,term_grace)
       if not drained:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        drained=owned_group_wait(child.pid,child,kill_grace)
      else:drained=True
      child.poll()
     except Exception as error:cleanup_error=type(error).__name__;drained=False
    reaped=child is None or child.returncode is not None
    passed=child is not None and child.returncode==0 and failure is None and received is None and not timed_out and not unexpected and drained and reaped
    outcome={'schema':'nakpanel-forward-owned-action-v1','source_vm':B['source_vm'],'run_token':B['run_token'],'runtime_commit':B['source_payload']['commit'],'operation':state['operation'],'status':'passed' if passed else 'failed','action_pid':child.pid if child else None,'action_pgid':child.pid if child else None,'started':child is not None,'exit_code':child.returncode if child else None,'timed_out':timed_out,'interrupted':received is not None or isinstance(failure,KeyboardInterrupt),'termination_signal':received,'unexpected_descendants':unexpected,'owned_group_empty':drained,'leader_reaped':reaped,'started_at':started,'finished_at':utc()}
    if failure is not None:outcome['error_type']=type(failure).__name__
    if cleanup_error is not None:outcome['cleanup_error_type']=cleanup_error
    state['action_tree']=outcome;publish(path,outcome);state['action_receipt']=file_ref(path)
  finally:
   for signum,handler in previous.items():signal.signal(signum,handler)
  require(drained and reaped,'owned action group drain is unconfirmed; no source stop or handoff authorized')
  if received is not None:raise ControlledTermination('cancellation before action handoff',received)
  if failure is not None:raise failure
  require(passed,'owned action failed or left unexpected descendants; inspect private outcome')
  result=subprocess.CompletedProcess(command,child.returncode)
  if received is not None:raise ControlledTermination('cancellation at action return',received)
  return result
 except BaseException as error:
  if received is not None or isinstance(error,KeyboardInterrupt):publish_terminal_cancellation(error)
  raise


def file_ref(path):return {'path':str(path),'sha256':sha(path)}

def public_result(state):
    # New fixed projection only. Never copy arbitrary child output/JSON values.
    r={'schema':'nakpanel-hosted-forward-result-v1','status':'PASS' if state.get('status')=='PASS' else 'FAIL','scope':'fresh-synthetic-native-forward','source_commit':COMMIT,'source_tree':TREE,'production_qualified':False,'fresh_source_full17_claim':False,'post_job_source_retained':False,'target_reboots':1 if state.get('target_reboot_verified') is True else 0,'planned_target_reboots':1,'dynamic_zero_writes_instrumentation':False,'resources':{'maximum_simultaneous_guests':2,'source':{'cpus':2,'memory':'5G','disk':'32G'},'target':{'cpus':2,'memory':'5G','disk':'32G'}},'stages':[]}
    if state.get('qualifier_identity')==QUALIFIER_IDENTITY:r['qualifier_identity']=dict(QUALIFIER_IDENTITY)
    for row in state.get('stages',[]):
        if type(row) is dict and row.get('stage') in CAPS and (type(row.get('exit_code')) is int or row.get('exit_code') is None):r['stages'].append(dict(stage=row['stage'],exit_code=row['exit_code'],**{k:row.get(k) is True for k in ('owned_group_empty','leader_reaped','timed_out','interrupted')}))
    for key in ('negative_missing_php','negative_archive_sha256','positive_archive_sha256','manifest_sha256','public_key_sha256','source_boot_id','target_boot_id'):
        value=state.get(key)
        if type(value) is str and (SHA.fullmatch(value) or (key=='negative_missing_php' and re.fullmatch(r'8\.[234]',value)) or (key.endswith('boot_id') and re.fullmatch('[a-f0-9-]{36}',value))):r[key]=value
    for key in ('source_vm','negative_vm','positive_vm'):
        value=state.get(key)
        if type(value) is str and re.fullmatch('nakpanel-[A-Za-z0-9-]{1,120}',value):r[key]=value
    value=state.get('run_token')
    if type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]{5,63}',value):r['run_token']=value
    for key in ('workflow_run_id','workflow_run_attempt'):
        if type(state.get(key)) is str and re.fullmatch('[0-9]{1,20}',state[key]):r[key]=state[key]
    r['actual_guest_allocations']=[]
    for row in state.get('actual_guest_allocations',[]):
        if type(row) is dict and row.get('role') in ('source','negative','positive') and type(row.get('vm')) is str and re.fullmatch('nakpanel-[A-Za-z0-9-]{1,120}',row['vm']) and all(type(row.get(k)) is int and 0<row[k]<=64*2**30 for k in ('cpu_count','memory_bytes','root_disk_bytes')):
            r['actual_guest_allocations'].append({k:row[k] for k in ('role','vm','cpu_count','memory_bytes','root_disk_bytes')})
    host=state.get('host_admission')
    if type(host) is dict and all(type(host.get(k)) is int and 0<host[k]<2**60 for k in ('cpu_count','total_memory','available_memory','free_disk','kvm_api')):r['host_admission']={k:host[k] for k in ('cpu_count','total_memory','available_memory','free_disk','kvm_api')}
    r['cleanup_completed']=state.get('cleanup_completed') is True
    for key in ('ordered_negative_check_only','positive_restore_verified','source_unchanged','target_reboot_verified'):r[key]=state.get(key) is True
    for key in ('controller_commit','workflow_commit'):
        if re.fullmatch('[a-f0-9]{40}',state.get(key,'')):r[key]=state[key]
    for key in ('admission_sha256','command_sources_inventory_sha256'):
        if SHA.fullmatch(state.get(key,'')):r[key]=state[key]
    for key in ('current_boundary','last_completed_boundary','failure_boundary'):
        r[key]=state.get(key) if type(state.get(key)) is str and state.get(key) in BOUNDARIES else 'UNKNOWN'
    r['failure_predicate']=state.get('failure_predicate') if type(state.get('failure_predicate')) is str and state.get('failure_predicate') in PREDICATES else 'UNKNOWN'
    r['failure_kind']=state.get('failure_kind') if type(state.get('failure_kind')) is str and state.get('failure_kind') in {'semantic','command','cancelled','deadline'} else 'UNKNOWN'
    r['failure_code']=state.get('failure_code') if state.get('failure_code') in {'admission_refused','stage_failed','cancelled','cleanup_failed','deadline','input_drift'} else (None if r['status']=='PASS' else 'stage_failed')
    r['primary_outcome'],r['cleanup_outcome']=outcomes_projection(state)
    return r

class Runner:
    def __init__(self,root,env,binding,budget=None):self.root=Path(root);self.env=env;self.binding=binding;self.budget=budget or Budget();self.rows=[];self.counter=0;self.last_tree_empty=True;self.before=lambda stage:None
    def call(self,stage,args,*,data=None,env=None,accepted=(0,)):
        self.before(stage);self.counter+=1;folder=self.root/'logs';folder.mkdir(mode=0o700,exist_ok=True);prefix=folder/(str(self.counter)+'-'+stage)
        inp=None
        if data is not None:
            inp=Path(str(prefix)+'.stdin');inp.write_bytes(data if isinstance(data,bytes) else data.encode());inp.chmod(0o600)
        stdout=Path(str(prefix)+'.stdout');stderr=Path(str(prefix)+'.stderr');state={'operation':stage}
        # Existing owned_action takes file descriptors, and Popen inherits stdin
        # via an explicit duplicate-free pre-opened fd, never command-line secrets.
        read=None
        command=list(map(str,args))
        if inp is not None:
            # A fixed tiny shim sets fd0 then execs the intended argv in the SAME
            # session/group; no shell quoting or new process/session is introduced.
            command=[sys.executable,'-I','-B','-c','import os,sys;f=os.open(sys.argv[1],os.O_RDONLY);os.dup2(f,0);os.close(f);os.execvpe(sys.argv[2],sys.argv[2:],os.environ)',str(inp),*command]
        try:
            with stdout.open('xb') as out,stderr.open('xb') as err:
                os.chmod(stdout,0o600);os.chmod(stderr,0o600)
                try:owned_action(self.binding,self.root,state,command,env or self.env,stdout=out,stderr=err,timeout=self.budget.allowance(stage))
                except Refusal:
                    tree=state.get('action_tree',{})
                    if type(tree.get('exit_code')) is not int or tree['exit_code'] not in accepted or not tree.get('owned_group_empty') or tree.get('unexpected_descendants') or tree.get('interrupted') or tree.get('timed_out'):raise
        finally:
            if read:read.close()
            tree=state.get('action_tree',{});self.last_tree_empty=tree.get('owned_group_empty') is True and tree.get('leader_reaped') is True
            self.rows.append(dict(stage=stage,**{k:tree.get(k) for k in ('exit_code','owned_group_empty','leader_reaped','timed_out','interrupted')}))
        self.budget.check(stage);self.before(stage)
        code=state['action_tree']['exit_code'];require(code in accepted,'command returned an unexpected exit')
        return code,stdout,stderr
    def output(self,stage,args,**kw):
        code,out,err=self.call(stage,args,**kw);return out.read_text()

# Read-only witness only: root-owned platform state, three actual executables,
# individual unit observations, physical SQL and a stable logical DB fingerprint.
PROOF=r'''import hashlib,json,os,pathlib,stat,subprocess
paths={'panel':'/usr/local/bin/nakpanel-panel','agent':'/usr/local/bin/nakpanel-agent','panelctl':'/usr/local/bin/panelctl'}
r={'binaries':{},'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
for k,p in paths.items():
 s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise SystemExit('untrusted installed executable')
 r['binaries'][k]=hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
r['platform']=json.loads(pathlib.Path('/etc/nakpanel/platform.json').read_text())
r['architecture']=subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()
r['units']={}
for u in ['nakpanel.service','nakpanel-agent.service','nginx.service','postgresql.service','mariadb.service','named.service','stalwart-mail.service','nakpanel-proftpd.service']:
 p=subprocess.run(['systemctl','is-active',u],capture_output=True,text=True,timeout=10);r['units'][u]=p.stdout.strip()
q="SELECT json_build_object('sites',(SELECT COALESCE(json_agg(json_build_array(id,domain,php_version,desired_php_version,desired_status) ORDER BY id),'[]'::json) FROM sites),'plans',(SELECT COALESCE(json_agg(json_build_array(id,revision) ORDER BY id),'[]'::json) FROM plans),'schema',(SELECT max(version_id) FROM goose_db_version))::text"
sql=subprocess.check_output(['runuser','-u','postgres','--','psql','-XAtq','-d','nakpanel','-c',q],text=True,timeout=20)
r['database_fingerprint']=hashlib.sha256(sql.encode()).hexdigest()
print(json.dumps(r,sort_keys=True))'''

class Coordinator:
    def __init__(self,a,app,controller,private,public,env=None):
        self.a=a;self.app=Path(app);self.controller=Path(controller);self.root=Path(private);self.public=Path(public);self.host=dict(os.environ if env is None else env);self.state={'status':'STARTED','stages':[]};self.pins={};self.known={};self.staged=None;self.private_created=False;self.public_created=False
        self.bash='/usr/bin/bash';self.python=sys.executable;self.token=None;self.bundle=None;self.key=None
        self._work_operation='UNKNOWN';self._proof_count=0;self._proof_failure=None;self._proof_observation=None;self._preparation_failure=None;self._source_phase_failure=None
        self.state.update(primary_outcome={'status':'not_run'},cleanup_outcome={'status':'not_run','failures':[]})
    def boundary(self,name):
        require(name in BOUNDARIES,'unknown fixed boundary');self.state['current_boundary']=name
    def remember_failure(self,error):
        if 'failure_boundary' in self.state:return
        self.state['failure_boundary']=self.state.get('current_boundary','UNKNOWN')
        self.state['failure_predicate']=error.predicate if isinstance(error,PredicateRefusal) else 'UNKNOWN'
        rows=self.run.rows if hasattr(self,'run') else []
        nonzero=bool(rows and type(rows[-1].get('exit_code')) is int and rows[-1]['exit_code']!=0)
        self.state['failure_kind']='semantic' if isinstance(error,PredicateRefusal) else 'deadline' if isinstance(error,Deadline) else 'cancelled' if isinstance(error,KeyboardInterrupt) else 'command' if nonzero else 'UNKNOWN'
    def failure_details(self,error):
        rows=self.run.rows if hasattr(self,'run') else []
        nonzero=bool(rows and type(rows[-1].get('exit_code')) is int and rows[-1]['exit_code']!=0)
        result={'boundary':self.state.get('current_boundary','UNKNOWN'),'predicate':error.predicate if isinstance(error,PredicateRefusal) else 'UNKNOWN','kind':'semantic' if isinstance(error,PredicateRefusal) else 'deadline' if isinstance(error,Deadline) else 'cancelled' if isinstance(error,KeyboardInterrupt) else 'command' if nonzero else 'UNKNOWN','command_count':len(rows)}
        pending=self._proof_failure
        if pending is not None and pending[0] is error:result['proof_observation']=pending[1]
        pending=self._source_phase_failure
        if pending is not None and pending[0] is error:result['source_phase_diagnostic']=pending[1]
        pending=self._preparation_failure
        if pending is not None and pending[0] is error:result['preparation_diagnostic']=pending[1]
        return failure_projection(result)
    def capture_primary(self,error=None):
        if self.state.get('primary_outcome',{}).get('status')!='not_run':return
        value=self.failure_details(error) if error is not None else failure_projection({'boundary':self.state.get('current_boundary'),'command_count':len(self.run.rows) if hasattr(self,'run') else 0})
        self.state['primary_outcome']=dict(status='failed' if error is not None else 'passed',**value)
    def cleanup_failure(self,role,error):
        outcome=self.state['cleanup_outcome'];outcome['status']='failed'
        if len(outcome['failures'])<4:outcome['failures'].append(dict(role=closed(role,{'source','negative','positive','private_staging'}),**self.failure_details(error)))
    def proof_note(self,key,value):
        # Observation-only: malformed/unavailable diagnostics never become a gate.
        try:
            if self._proof_observation is not None and key in CHECK_KEYS and type(value) is bool:self._proof_observation['checks'][key]=value
        except Exception:pass
    def proof_context(self,name,stage):
        if type(stage) is not str:return 'UNKNOWN'
        if name==getattr(self,'source',None):return stage if stage in {'current','phase28','phase30','negative_backup','prepare'} else 'positive_source' if stage=='positive' else 'UNKNOWN'
        if name==getattr(self,'negative',None) and stage=='negative_check':return 'negative_target'
        if name==getattr(self,'positive_vm',None) and stage=='positive':return 'positive_target'
        return 'UNKNOWN'
    def list_names(self,row,prefix):
        self.boundary(prefix+'_object');predicate_require(type(row) is dict,prefix+'_object')
        self.boundary(prefix+'_errors');predicate_require('errors' not in row or (type(row['errors']) is list and row['errors']==[]),prefix+'_errors')
        self.boundary(prefix+'_rows');predicate_require(type(row.get('list')) is list,prefix+'_rows')
        names=[]
        for item in row['list']:
            predicate_require(type(item) is dict and type(item.get('name')) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,127}',item['name']),prefix+'_rows');names.append(item['name'])
        predicate_require(len(names)==len(set(names)),prefix+'_rows');return names
    def environment(self):
        allowed=('PATH','HOME','LANG','LC_ALL','TMPDIR','RUNNER_TEMP','GITHUB_ENV','GITHUB_ACTIONS','RUNNER_ENVIRONMENT','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY','GITHUB_SHA','CONTROLLER_SHA')
        e={k:self.host[k] for k in allowed if k in self.host};e.update(PYTHONDONTWRITEBYTECODE='1',GOTOOLCHAIN='go1.26.9',NAKPANEL_QUALIFICATION_PHP_PROVIDER='native',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_MULTIPASS_IMAGE='24.04',NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_FORWARD_ALLOW_DEVELOPMENT='1')
        return e
    def git(self,root,*args):return self.run.output('artifact',['git','-C',root,*args]).strip()
    def checkout(self,root,commit,tree,expected):
        require(self.git(root,'rev-parse','HEAD')==commit,'checkout commit differs')
        if tree:require(self.git(root,'rev-parse','HEAD^{tree}')==tree,'checkout tree differs')
        require(not self.git(root,'status','--porcelain','--untracked-files=all'),'checkout dirty')
        names=self.git(root,'ls-files','-z','deploy/multipass').split('\0') if root==self.app else list(expected)
        names={n for n in names if n};names.update(['deploy/release/verify.py','deploy/install/platform.sh','deploy/install/platform_state.py'] if root==self.app else [])
        require(set(expected)==names,'complete helper inventory differs')
        for name,h in expected.items():
            p=regular(root/name)
            # Git command output is text; avoid newline/encoding normalization by
            # hashing the retained byte stdout, not the convenience text result.
            code,out,err=self.run.call('artifact',['git','-C',root,'show',commit+':'+name]);require(sha(p)==sha(out)==h,'helper differs from committed blob');self.pins[str(p)]=h
        require(not any(root.rglob('__pycache__')),'foreign source bytecode cache')
    def shell(self,stage,body,*args,env=None,data=None,accepted=(0,)):
        return self.run.call(stage,[self.bash,'-ceu','set -euo pipefail; source "$APP_SOURCE/deploy/multipass/common.sh"; '+body,'--',*args],env=env,data=data,accepted=accepted)
    def jshell(self,stage,body,*args,env=None):return decoded(self.shell(stage,body,*args,env=env)[1].read_bytes())
    def require_live_host(self):
        require(platform.system()=='Linux' and platform.machine() in ('x86_64','amd64') and self.host.get('GITHUB_ACTIONS')=='true' and self.host.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable hosted Linux AMD64 required')
        require(self.host.get('GITHUB_REPOSITORY')==self.a['repository'] and self.host.get('CONTROLLER_SHA')==self.a['controller_commit'],'workflow controller/repository differs')
        require(all(re.fullmatch('[0-9]+',self.host.get(k,'')) for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')),'actual workflow identity missing')
    def setup(self):
        self.require_live_host();check_paths(self.app,self.controller,self.root,self.public,Path(self.host['RUNNER_TEMP']));os.umask(0o077);require(not self.root.exists() and not self.public.exists(),'new private/public outputs must not exist')
        self.root.mkdir(mode=0o700);self.private_created=True;self.public.mkdir(mode=0o700);self.public_created=True
        self.token='hosted-forward-'+self.host['GITHUB_RUN_ID']+'-'+self.host['GITHUB_RUN_ATTEMPT']+'-'+self.a['nonce'][:8]
        require(len(self.token)<=64,'ownership token too long')
        self.source='nakpanel-24-04-amd64-'+self.token;self.negative='nakpanel-negative-'+self.token;self.positive_vm='nakpanel-positive-'+self.token
        self.state.update(source_vm=self.source,negative_vm=self.negative,positive_vm=self.positive_vm,run_token=self.token,workflow_run_id=self.host['GITHUB_RUN_ID'],workflow_run_attempt=self.host['GITHUB_RUN_ATTEMPT'])
        env=self.environment();env.update(APP_SOURCE=str(self.app),NAKPANEL_RUN_TOKEN=self.token,NAKPANEL_MULTIPASS_VM=self.source,NAKPANEL_MULTIPASS_SOURCE_VM=self.source,NAKPANEL_MULTIPASS_DR_VM=self.negative,NAKPANEL_OWNERSHIP_DIR=str(self.root/'owners'),NAKPANEL_QUALIFICATION_VM_CPUS='2',NAKPANEL_QUALIFICATION_VM_MEMORY='5G',NAKPANEL_QUALIFICATION_VM_DISK='32G',NAKPANEL_QUALIFICATION_DR_CPUS='2',NAKPANEL_QUALIFICATION_DR_MEMORY='5G',NAKPANEL_QUALIFICATION_DR_DISK='32G')
        self.state.update(controller_commit=self.a['controller_commit'],workflow_commit=self.host.get('GITHUB_SHA',''),command_sources_inventory_sha256=digest(canonical(self.a['app_helpers'])))
        self.run=Runner(self.root,env,{'source_vm':self.source,'run_token':self.token,'source_payload':{'commit':COMMIT}})
        child_bash=self.run.output('artifact',[self.bash,'-c','((BASH_VERSINFO[0]>=5)) && command -v bash']).strip();require(os.path.samefile(child_bash,self.bash),'nested Bash interpreter differs')
        self.checkout(self.controller,self.a['controller_commit'],None,self.a['controller_files']);self.checkout(self.app,COMMIT,TREE,self.a['app_helpers'])
        self.state['qualifier_identity']=qualifier_artifacts(self.controller,self.app)['identity'];self.run.before=self.guard
    def guard(self,stage):
        check_pins(self.pins)
        if stage!='cleanup':require(datetime.now(timezone.utc)<instant(self.a['expires_at']),'launch admission expired before transition')
    def acquire(self):
        a=self.a;repo=a['repository'];ar=a['artifact'];ghenv=dict(self.run.env);require(type(self.host.get('GH_TOKEN')) is str and bool(self.host['GH_TOKEN']),'read-only artifact token missing');ghenv['GH_TOKEN']=self.host['GH_TOKEN']
        row=decoded(self.run.output('artifact',['gh','api','--hostname','github.com',f'/repos/{repo}/actions/artifacts/{ar["id"]}'],env=ghenv));check_artifact(row,a)
        code,z,_=self.run.call('artifact',['gh','api','--hostname','github.com',f'/repos/{repo}/actions/artifacts/{ar["id"]}/zip'],env=ghenv)
        require(z.stat().st_size==ar['size'] and sha(z)==ar['sha256'],'actual original ZIP digest/size differs');self.pins[str(z)]=sha(z)
        dst=self.root/'download';extract_zip(z,dst);archive=regular(dst/a['payload']['archive']);require(archive.stat().st_size==a['payload']['archive_size'] and sha(archive)==a['payload']['archive_sha256'],'inner current archive differs')
        self.pins[str(archive)]=sha(archive);extract_tar(archive,self.root/'release');self.bundle=self.root/'release'/'nakpanel-29.0.0-linux-amd64';self.key=regular(dst/'test-public.pem')
        require(sha(self.bundle/'manifest.json')==a['payload']['manifest_sha256'] and sha(self.key)==a['payload']['public_key_sha256'],'manifest/public trust key differs')
        manifest=decoded((self.bundle/'manifest.json').read_bytes());require(manifest.get('commit')==COMMIT and manifest.get('development') is True and manifest.get('go_toolchain')=='go1.26.9','manifest source/toolchain/development differs')
        self.run.call('artifact',[self.python,'-I','-B',self.app/'deploy/release/verify.py','--bundle',self.bundle,'--public-key',self.key,'--version','29.0.0','--architecture','amd64','--allow-development'])
        require(type(manifest.get('files')) is dict and len(manifest['files'])==173,'signed release inventory differs')
        for name,h in manifest['files'].items():
            if name.startswith('bin/'):
                require(name in {'bin/'+n+s for n in BINARY_PATHS for s in ('','.buildinfo')},'unexpected binary artifact')
                if not name.endswith('.buildinfo'):require(h==a['payload']['binaries'][name[4:]],'signed selected binary differs')
            else:require(sha(self.app/name)==h,'release asset differs from current source')
            self.pins[str(self.bundle/name)]=h
        for n in BINARY_PATHS:
            code,p,_=self.run.call('artifact',['go','version','-m',self.bundle/'bin'/n]);actual=p.read_text().splitlines();signed=(self.bundle/'bin'/(n+'.buildinfo')).read_text().splitlines();require(actual[1:]==signed[1:] and actual[0].endswith(': go1.26.9'),'signed binary buildinfo differs')
        for p in (self.bundle/'manifest.json',self.bundle/'manifest.sig',self.key):self.pins[str(p)]=sha(p)
        self.state.update(manifest_sha256=sha(self.bundle/'manifest.json'),public_key_sha256=sha(self.key))
        self.run.env.update(NAKPANEL_RELEASE_BUNDLE=str(self.bundle),NAKPANEL_RELEASE_PUBLIC_KEY=str(self.key),NAKPANEL_RELEASE_VERSION='29.0.0')
    def host_prepare(self):
        self.run.call('host',[self.bash,self.app/'deploy/multipass/prepare-hosted-runner.sh'])
        # Read ONLY TMPDIR from the new helper-produced GITHUB_ENV protocol.
        lines=Path(self.host['GITHUB_ENV']).read_text().splitlines();paths=[s[7:] for s in lines if s.startswith('TMPDIR=')]
        require(paths,'private snap-visible TMPDIR missing');p=Path(paths[-1]);s=p.lstat();base=Path(self.host['RUNNER_TEMP']).resolve()
        require(p.is_absolute() and p.resolve()==p and base in p.parents and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'untrusted hosted TMPDIR')
        self.run.env['TMPDIR']=str(p)
    def images(self):
        dst=self.root/'download'
        for release,(suite,serial,h) in IMAGES.items():
            metadata=dst/'images'/suite
            self.run.call('images',['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',metadata/'SHA256SUMS.gpg',metadata/'SHA256SUMS'])
            filename='ubuntu-'+release+'-server-cloudimg-amd64.img';rows=[line.split()[0] for line in (metadata/'SHA256SUMS').read_text().splitlines() if len(line.split())==2 and line.split()[1].lstrip('*')==filename];require(rows==[h],'image pin differs from signed manifest')
            url=f'https://cloud-images.ubuntu.com/releases/{suite}/release-{serial}/{filename}';target=self.root/filename
            self.run.call('images',['curl','--fail','--location','--proto','=https','--proto-redir','=https','--max-time','600',url,'--output',target]);require(sha(target)==h,'image bytes differ');self.pins[str(target)]=h
            prefix='NAKPANEL_MULTIPASS_IMAGE_' if release=='24.04' else 'NAKPANEL_FORWARD_TARGET_IMAGE_';self.run.env.update({prefix+'SOURCE':str(target),prefix+'SHA256':h})
        path=self.root/'host-preflight.json';self.run.call('admit',[self.python,'-I','-B',self.app/'deploy/multipass/hosted-runner-preflight.py','--output',path]);row=decoded(path.read_bytes());check_capacity(row);self.state['host_admission']={k:row[k] for k in ('cpu_count','total_memory','available_memory','free_disk','kvm_api')};row['requested_forward_budget']={'maximum_guests':2,'source':{'cpus':2,'memory':'5G','disk':'32G'},'target':{'cpus':2,'memory':'5G','disk':'32G'}};publish(self.root/'forward-capacity.json',row)
    def check_new_vm(self,name,stage):
        caller=self.state.get('current_boundary');self.boundary('vm_list_command');text=self.run.output(stage,['multipass','list','--format','json']);self.boundary('vm_list_json');row=decoded(text)
        names=self.list_names(row,'vm_list');require(name not in names and set(names)<=set(self.known),'unexpected/preexisting VM; refuse allocation/adoption')
        if caller is None:self.state.pop('current_boundary',None)
        else:self.state['current_boundary']=caller
    def owner(self,name,release):check_owner(self.root/'owners'/self.token/name,release,self.token)
    def proof(self,name,release,stage,frozen=False):
        caller=self.state.get('current_boundary');self._proof_count+=1
        self._proof_failure=None;self._proof_observation={'invocation':self._proof_count,'context':self.proof_context(name,stage),'active':True,'json_decoded':False,'checks':{}}
        self.state['proof_observation']=proof_projection(self._proof_observation);passed=False
        try:
            self.boundary('proof_owner');self.owner(name,release)
            self.boundary('proof_pins');check_pins(self.pins)
            self.boundary('proof_command');code,out,_=self.shell(stage,'assert_vm_identity "$1" "$2" amd64 "$NAKPANEL_RUN_TOKEN"; multipass exec "$1" -- sudo python3 -c "$3"',name,release,PROOF)
            self.boundary('proof_json');row=decoded(out.read_bytes());self._proof_observation['json_decoded']=True
            p=row.get('platform',{});expected='ubuntu-24.04' if release=='24.04' else 'ubuntu-26.04-native'
            self.boundary('proof_binaries');ok=row.get('binaries')==self.a['payload']['binaries'];self.proof_note('binary_inventory_matches',ok)
            if type(row.get('binaries')) is dict:
                for k in ('panel','agent','panelctl'):self.proof_note(k+'_matches',row['binaries'].get(k)==self.a['payload']['binaries'].get(k))
            predicate_require(ok,'source_binary_inventory')
            self.boundary('proof_architecture');ok=row.get('architecture')=='amd64';self.proof_note('architecture_matches',ok);predicate_require(ok,'source_architecture')
            self.boundary('proof_profile');ok=p.get('profile')==expected;self.proof_note('profile_matches',ok);predicate_require(ok,'source_profile')
            self.boundary('proof_version');ok=p.get('version_id')==release;self.proof_note('version_matches',ok);predicate_require(ok,'source_version')
            self.boundary('proof_database');ok=type(row.get('database_fingerprint')) is str and SHA.fullmatch(row['database_fingerprint']);self.proof_note('database_fingerprint_valid',bool(ok));predicate_require(ok,'source_database_fingerprint')
            self.boundary('proof_boot');ok=re.fullmatch('[a-f0-9-]{36}',row.get('boot_id',''));self.proof_note('boot_id_valid',bool(ok));predicate_require(ok,'source_boot_id')
            if not frozen:
                self.boundary('proof_units');units=row.get('units')
                # The original conjunction evaluates first. In particular an
                # unhashable malformed value still raises before any override.
                ok=type(units) is dict and len(units)==8 and set(units.values())=={'active'}
                eligible=type(stage) is str and ((name==getattr(self,'source',None) and ((self._work_operation=='source_phases' and stage in {'current','phase28','phase30'}) or (self._work_operation=='negative_backup' and stage=='negative_backup'))) or (name==getattr(self,'negative',None) and self._work_operation=='negative_target' and stage=='negative_check'))
                if not ok and eligible:ok=type(units) is dict and len(units)==8 and all(type(v) is str for v in units.values()) and all(units.get(u)=='active' for u in CORE_SEVEN)
                self.proof_note('units_predicate',ok)
                if type(units) is dict:
                    for alias,unit in SERVICE_ALIASES.items():self.proof_note(alias,units.get(unit)=='active')
                predicate_require(ok,'source_units')
            publish(self.root/(stage+'-'+name+'-proof.json'),row);passed=True;return row
        except BaseException as error:
            self._proof_failure=(error,proof_projection(self._proof_observation));raise
        finally:
            self._proof_observation['active']=False;self.state['proof_observation']=proof_projection(self._proof_observation);self._proof_observation=None
            if passed:
                if caller is None:self.state.pop('current_boundary',None)
                else:self.state['current_boundary']=caller
    def observed_budget(self,name,stage):
        row=decoded(self.run.output(stage,['multipass','info',name,'--format','json']));require(row.get('errors')==[] and set(row.get('info',{}))=={name},'actual VM budget record differs');i=row['info'][name]
        def number(x):require(type(x) is int or (type(x) is str and x.isdigit()),'invalid actual allocation');return int(x)
        cpu=number(i.get('cpu_count'));mem=number(i.get('memory',{}).get('total'));disks=i.get('disks');require(type(disks) is dict and disks,'actual disk observation missing');size=max(number(v.get('total')) for v in disks.values())
        require(cpu==2 and 4_800_000_000<=mem<=5.5*2**30 and 28_000_000_000<=size<=34.5*2**30,'observed guest allocation differs from requested2/5G/32G')
        self.state.setdefault('actual_guest_allocations',[]).append({'role':{self.source:'source',self.negative:'negative',self.positive_vm:'positive'}[name],'vm':name,'cpu_count':cpu,'memory_bytes':mem,'root_disk_bytes':size})
        publish(self.root/(name+'-allocation.json'),{'requested':{'cpus':2,'memory':'5G','disk':'32G'},'observed':{'cpu_count':cpu,'memory_bytes':mem,'root_disk_bytes':size}})
    def source_command(self,stage,body):
        self._source_phase_failure=None;before=len(self.run.rows);ordinal=self.run.counter+1
        try:return self.shell(stage,body)
        except BaseException as error:
            row=self.run.rows[-1] if len(self.run.rows)==before+1 else {};counter=getattr(self.run,'counter',None)
            known=stage in ('current','phase28','phase30') and type(counter) is int and counter==ordinal and row.get('stage')==stage and type(row.get('exit_code')) is int and row['exit_code']!=0 and row.get('owned_group_empty') is True and row.get('leader_reaped') is True and row.get('timed_out') is False and row.get('interrupted') is False
            try:diagnostic=source_log_diagnostic(self.root,stage,ordinal,self.app,self.bundle) if known else source_log_unknown(stage,ordinal)
            except Exception:diagnostic=source_log_unknown(stage,ordinal)
            self._source_phase_failure=(error,diagnostic)
            raise
    def source_phases(self):
        self.check_new_vm(self.source,'current');self.known[self.source]='24.04'
        self.boundary('source_current_run');self.source_command('current','init_qualification_run; exec "$BASH" "$APP_SOURCE/deploy/multipass/current-install-verify.sh"')
        self.boundary('source_budget');self.observed_budget(self.source,'current');self.proof(self.source,'24.04','current')
        for stage in ('phase28','phase30'):
            self.boundary('source_'+stage+'_run');check_pins(self.pins);self.source_command(stage,'export NAKPANEL_SKIP_PRIOR_PHASES=1; exec "$BASH" "$APP_SOURCE/deploy/multipass/'+stage+'-verify.sh"');self.proof(self.source,'24.04',stage)
    def operator(self,*args):
        return ['multipass','exec',self.source,'--','sudo','runuser','-u','nakpanel','--','env','NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable','NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock','NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json','panelctl','--actor','task10-forward',*args]
    def negative_backup(self):
        self.proof(self.source,'24.04','negative_backup');dest='forward-negative-'+self.a['nonce'][:12]
        count=self.run.output('negative_backup',['multipass','exec',self.source,'--','sudo','-u','postgres','psql','-XAtq','-d','nakpanel','-c',"SELECT count(*) FROM server_backup_destinations WHERE name='"+dest+"'"]).strip();require(count=='0','negative backup destination already exists')
        text=self.run.output('negative_backup',self.operator('backup-server','key','init'));lines=[s for s in text.splitlines() if re.fullmatch('nkbk1-[A-Z2-7]{52}',s)];require(len(lines)==1,'one-time backup key output invalid');self.negkey=self.root/'negative.key';self.negkey.write_text(lines[0]+'\n');self.negkey.chmod(0o600)
        self.run.call('negative_backup',self.operator('backup-server','destination','add','--name',dest,'--kind','local','--disabled','--settings','{"dir":"/var/lib/nakpanel/server-backups"}','--retention-count','1','--retention-days','0'))
        self.run.call('negative_backup',self.operator('backup-server','run','--destination',dest,'--wait','--timeout','12m'))
        sql="SELECT json_build_object('archive',b.archive_name,'size',b.size_bytes,'sha256',b.checksum_sha256,'verified',b.verified_at IS NOT NULL,'status',b.status,'detail',b.verify_detail) FROM server_backups b JOIN server_backup_destinations d ON d.id=b.destination_id WHERE d.name='"+dest+"' ORDER BY b.id"
        row=decoded(self.run.output('negative_backup',['multipass','exec',self.source,'--','sudo','-u','postgres','psql','-XAtq','-d','nakpanel','-c',sql]));require(row.get('status')=='active' and row.get('verified') is True and row.get('detail',{}).get('pg_restore_list_ok') is True and re.fullmatch(r'[A-Za-z0-9_.-]+\.nkbk',row.get('archive','')),'negative backup not verified')
        self.negarchive=self.root/'negative.nkbk';_,p,_=self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','cat','/var/lib/nakpanel/server-backups/'+row['archive']]);require(type(row.get('size')) is int and p.stat().st_size==row['size'] and sha(p)==row.get('sha256'),'negative archive physical digest/size differs');p.replace(self.negarchive)
        keyguest='/tmp/task10-negative-'+self.token+'.key';self.run.call('negative_backup',['multipass','transfer',self.negkey,self.source+':'+keyguest]);self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','chown','root:root',keyguest]);self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','chmod','600',keyguest])
        result=decoded(self.run.output('negative_backup',['multipass','exec',self.source,'--','sudo','panelctl','restore-server','--mode','same-platform','--check-only','--archive','/var/lib/nakpanel/server-backups/'+row['archive'],'--backup-key-file',keyguest]));require(result.get('compatible') is True and result.get('migration_qualified') is False,'negative archive authenticated inspection failed')
        self.missing=result.get('manifest',{}).get('platform',{}).get('required_php_versions');require(type(self.missing) is list and any(v in ('8.2','8.3','8.4') for v in self.missing),'archive lacks actual old PHP requirement')
        self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','rm','-f',keyguest]);self.state['negative_archive_sha256']=sha(self.negarchive)
        self.pins.update({str(self.negkey):sha(self.negkey),str(self.negarchive):sha(self.negarchive)})
    def prepare(self):
        check_pins(self.pins);spec=decoded(self.run.output('prepare',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--template']));spec.update(source_vm=self.source,run_token=self.token,architecture='amd64',target_profile='ubuntu-26.04-native',oci_image_ref=self.a['oci_image_ref'],normalize_php85=True,remediate_stale_php82=True)
        path=self.root/'spec.json';publish(path,spec);self.prepared=self.root/'prepared';self._preparation_failure=None;before=len(self.run.rows)
        nonce=os.urandom(16).hex();authkey=os.urandom(32).hex();ordinal=self.run.counter+1;companion=self.root/('prepare-preflight-'+nonce+'.json')
        try:self.run.call('prepare',[self.python,'-I','-B','-c',PREPARE_LAUNCHER,self.controller/'forward_hosted.py',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py',path,self.prepared,companion,nonce,str(ordinal),authkey,self.controller,self.source,self.token])
        except BaseException as error:
            # Observe the exact failed child without adding/replaying a call.
            # The early labels identify command categories, never a guard.
            row=self.run.rows[-1] if len(self.run.rows)==before+1 else {};counter=getattr(self.run,'counter',None)
            known=type(counter) is int and counter==ordinal and row.get('stage')=='prepare' and type(row.get('exit_code')) is int and row['exit_code']!=0 and row.get('owned_group_empty') is True and row.get('leader_reaped') is True and row.get('timed_out') is False and row.get('interrupted') is False
            stderr=self.root/'logs'/(str(counter)+'-prepare.stderr') if known else None
            diagnostic=preparation_diagnostic(self.prepared,stderr)
            observed=qualifier_companion(companion,nonce,ordinal,authkey,self.source,self.token) if known else qualifier_projection(None)
            expected={'source-preflight':'EARLY_SOURCE_PREFLIGHT_COMMAND','seed':'source-php-preparation-and-seed'}
            if observed['action']!='UNKNOWN' and expected.get(observed['action'])==diagnostic['stage']:diagnostic['qualifier_probe']=observed
            self._preparation_failure=(error,diagnostic)
            raise
        self.fixture=self.prepared/'fixture.json'
        self.run.env.update(NAKPANEL_FORWARD_FIXTURE_JSON=str(self.fixture),NAKPANEL_FORWARD_ARCHIVE=str(self.prepared/'source.nkbk'),NAKPANEL_FORWARD_KEY=str(self.prepared/'archive.key'),NAKPANEL_FORWARD_TARGET_BUNDLE=str(self.bundle),NAKPANEL_FORWARD_TARGET_PUBLIC_KEY=str(self.key),NAKPANEL_FORWARD_TARGET_VERSION='29.0.0')
        self.run.call('prepare',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--validate',self.fixture]);c=decoded(self.fixture.read_bytes());require(c.get('baseline') and c.get('archive_sha256')==sha(self.prepared/'source.nkbk'),'positive baseline/archive absent')
        for p in self.prepared.iterdir():
            if p.is_file():regular(p,True);self.pins[str(p)]=sha(p)
        self.state['positive_archive_sha256']=c['archive_sha256'];self.state['source_boot_id']=self.proof(self.source,'24.04','prepare',True)['boot_id']
    def target_env(self,name):
        e=dict(self.run.env);e.update(NAKPANEL_MULTIPASS_VM=name,NAKPANEL_MULTIPASS_DR_VM=name,NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_MULTIPASS_IMAGE_SOURCE=e['NAKPANEL_FORWARD_TARGET_IMAGE_SOURCE'],NAKPANEL_MULTIPASS_IMAGE_SHA256=e['NAKPANEL_FORWARD_TARGET_IMAGE_SHA256']);return e
    def stage(self,stage,name,target,env=None):
        folder=self.root/(target+'-evidence');folder.mkdir(mode=0o700,exist_ok=True)
        return self.run.call(stage,[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py',name,target,self.source,self.token,self.staged+'/bundle' if self.staged else self.bundle,folder],env=env)
    def headroom(self,stage):
        # Same runner measurement, without resetting initial KVM/capacity receipt.
        raw=self.run.output(stage,[self.python,'-I','-B','-c','import json,shutil;from pathlib import Path;m={s.split(":")[0]:int(s.split()[1])*1024 for s in Path("/proc/meminfo").read_text().splitlines()};print(json.dumps({"memory":m["MemAvailable"],"disk":shutil.disk_usage("/var/snap/multipass/common").free}))']);r=decoded(raw)
        require(type(r.get('memory')) is int and r['memory']>=6*2**30 and type(r.get('disk')) is int and r['disk']>=40*2**30,'insufficient remaining target memory/disk headroom')
    def negative_target(self):
        check_pins(self.pins);self.headroom('negative_install');self.check_new_vm(self.negative,'negative_install')
        self.staged=self.run.output('negative_install',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--stage-target-bundle',self.bundle,self.key,'29.0.0','amd64','1']).strip();require(Path(self.staged).is_dir(),'staged bundle missing');env=self.target_env(self.negative);env['NAKPANEL_FORWARD_TARGET_PUBLIC_KEY']=self.staged+'/public.pem'
        self.known[self.negative]='26.04';self.shell('negative_install','ensure_vm 4 8G 40G',env=env);self.observed_budget(self.negative,'negative_install');self.stage('negative_install','install-native-target',self.negative,env)
        self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','python3','-I','-B','-'],data=(self.app/'deploy/multipass/qualification_maintenance_ready.py').read_bytes())
        before=self.proof(self.negative,'26.04','negative_check');leaf='/tmp/task10-negative-'+self.token
        self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','install','-d','-m','0700',leaf])
        for p,n in ((self.negarchive,'archive.nkbk'),(self.negkey,'archive.key')):
            self.run.call('negative_check',['multipass','transfer',p,self.negative+':/home/ubuntu/task10-negative-'+self.token+'-'+n]);self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','install','-m','0600','/home/ubuntu/task10-negative-'+self.token+'-'+n,leaf+'/'+n]);self.run.call('negative_check',['multipass','exec',self.negative,'--','rm','-f','/home/ubuntu/task10-negative-'+self.token+'-'+n])
        actual=self.run.output('negative_check',['multipass','exec',self.negative,'--','sudo','sha256sum',leaf+'/archive.nkbk',leaf+'/archive.key']).splitlines();require(actual==[sha(self.negarchive)+'  '+leaf+'/archive.nkbk',sha(self.negkey)+'  '+leaf+'/archive.key'],'negative guest archive/key transfer differs')
        code,out,err=self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','panelctl','restore-server','--mode','forward-migration','--check-only','--archive',leaf+'/archive.nkbk','--backup-key-file',leaf+'/archive.key'],accepted=tuple(range(1,126)))
        self.state['negative_missing_php']=check_negative(code,err.read_text(),self.missing);self.state['ordered_negative_check_only']=True;after=self.proof(self.negative,'26.04','negative_check');require(before==after,'negative check changed observed logical DB/service/binary/boot state')
        self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','rm','-f',leaf+'/archive.key']);self.stage('negative_check','assert-no-source-writes',self.negative,env)
        self.delete(self.negative,'negative_check');self.run.call('negative_check',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--discard-target-bundle',self.staged]);self.staged=None
    def positive(self):
        self.boundary('positive_driver');check_pins(self.pins);self.headroom('positive');self.check_new_vm(self.positive_vm,'positive');self.known[self.positive_vm]='26.04';env=dict(self.run.env,NAKPANEL_MULTIPASS_DR_VM=self.positive_vm,NAKPANEL_FORWARD_KEEP_TARGET='1',NAKPANEL_FORWARD_EVIDENCE_DIR=str(self.root/'positive-evidence'))
        self.run.call('positive',[self.bash,self.app/'deploy/multipass/ubuntu-forward-migration-verify.sh'],env=env)
        self.boundary('positive_evidence');evidence=self.root/'positive-evidence';expected=['assert-source-readonly','install-native-target','assert-baseline','assert-migration-data','assert-services','assert-trusted-tls','assert-reboot','assert-migration-data','assert-trusted-tls','assert-no-source-writes']
        for n,name in enumerate(expected,1):predicate_require((evidence/(str(n)+'-'+name+'.log')).is_file(),'positive_stage_evidence')
        self.boundary('positive_preflight');restore=decoded((evidence/'restore.json').read_bytes());pre=decoded((evidence/'preflight.json').read_bytes());check_positive(pre,restore)
        self.boundary('positive_budget');self.observed_budget(self.positive_vm,'positive')
        self.boundary('positive_identity');proof=self.proof(self.positive_vm,'26.04','positive')
        self.boundary('positive_reboot');initial=(evidence/'initial-target-boot-id').read_text().strip();predicate_require(initial!=proof['boot_id'],'positive_target_reboot');self.state['target_boot_id']=proof['boot_id']
        self.boundary('source_unchanged');self.proof(self.source,'24.04','positive',True);self.state.update(positive_restore_verified=True,source_unchanged=True,target_reboot_verified=True)
    def delete(self,name,stage):
        self.boundary('cleanup_group');require(self.run.last_tree_empty,'action descendants remain; cleanup refused')
        self.boundary('cleanup_initial_command');text=self.run.output(stage,['multipass','list','--format','json']);self.boundary('cleanup_initial_json');listing=decoded(text);names=self.list_names(listing,'cleanup_initial')
        if name not in names:self.known.pop(name);return
        release=self.known[name];self.boundary('proof_owner');self.owner(name,release)
        env=dict(self.run.env,NAKPANEL_MULTIPASS_DR_VM=name if name!=self.source else self.positive_vm)
        self.boundary('cleanup_destroy');self.shell(stage,'destroy_owned_vm "$1" "$NAKPANEL_RUN_TOKEN"',name,env=env)
        self.boundary('cleanup_final_command');text=self.run.output(stage,['multipass','list','--format','json']);self.boundary('cleanup_final_json');row=decoded(text);names=self.list_names(row,'cleanup_final')
        self.boundary('cleanup_final_absence');predicate_require(name not in names,'cleanup_final_absence');self.known.pop(name)
    def cleanup(self):
        self.boundary('cleanup_group');require(self.run.last_tree_empty,'cannot clean guests before owned group drain')
        errors=[]
        for name in list(self.known)[::-1]:
            # Never adopt or delete a launch whose ownership cannot be proven.
            try:self.delete(name,'cleanup')
            except Exception as error:
                errors.append(name);role='source' if name==getattr(self,'source',None) else 'negative' if name==getattr(self,'negative',None) else 'positive' if name==getattr(self,'positive_vm',None) else 'UNKNOWN';self.cleanup_failure(role,error)
        if self.staged:
            try:self.run.call('cleanup',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--discard-target-bundle',self.staged])
            except Exception as error:errors.append('private-staging');self.cleanup_failure('private_staging',error)
        require(not errors,'owned cleanup failed');self.state['cleanup_completed']=True;self.state['cleanup_outcome']['status']='passed'
    def execute(self):
        previous={};error=None;received=None;phase='work';self.state['started_at']=utc()
        def terminate(signum,frame):
            nonlocal received
            if received is None:received=signum
            if phase in ('work','returning'):raise ControlledTermination('coordinator cancelled',signum)
        def write_result():
            if self.private_created:publish(self.root/'private-result.json',self.state)
            if self.public_created:publish(self.public/'result.json',public_result(self.state))
        def cancelled_result():
            nonlocal error
            if received is not None:
                error=ControlledTermination('coordinator cancellation before return',received)
                self.remember_failure(error)
                self.state.update(status='FAIL',failure_code='cancelled',termination_signal=received)
                return True
            return False
        try:
            for signum in (signal.SIGINT,signal.SIGTERM):previous[signum]=signal.signal(signum,terminate)
            try:
                for boundary,action in [('setup',self.setup),('artifact',self.acquire),('host',self.host_prepare),('images',self.images),('source',self.source_phases),('negative_backup',self.negative_backup),('prepare',self.prepare),('negative_target',self.negative_target),('positive',self.positive)]:
                    self._work_operation={'source':'source_phases','negative_backup':'negative_backup','negative_target':'negative_target'}.get(boundary,'UNKNOWN')
                    self.boundary(boundary);action();self.state['last_completed_boundary']=boundary
                predicate_require(all(self.state.get(k) is True for k in ('ordered_negative_check_only','positive_restore_verified','source_unchanged','target_reboot_verified')),'terminal_outcomes');self.state['status']='PASS';self.capture_primary()
            except BaseException as e:
                error=e;self.remember_failure(e);self.capture_primary(e);self.state.update(status='FAIL',failure_code='cancelled' if isinstance(e,KeyboardInterrupt) else 'stage_failed')
                if isinstance(e,KeyboardInterrupt) and received is None:received=getattr(e,'signum',signal.SIGINT)
            self._work_operation='UNKNOWN';phase='cleanup';self.boundary('cleanup')
            if hasattr(self,'run'):
                try:self.cleanup();self.state['cleanup_outcome']['status']='passed';self.state['last_completed_boundary']='cleanup'
                except BaseException as e:
                    if not self.state['cleanup_outcome']['failures']:self.cleanup_failure('UNKNOWN',e)
                    self.remember_failure(e);self.state.update(status='FAIL',failure_code='cleanup_failed');error=error or e
                    if isinstance(e,KeyboardInterrupt) and received is None:received=getattr(e,'signum',signal.SIGINT)
                self.state['stages']=self.run.rows
            if hasattr(self,'run'):self.run.budget.check('cleanup')
            self.state['finished_at']=utc();self.boundary('publication');cancelled_result();write_result()
            if hasattr(self,'run'):self.run.budget.check('cleanup')
            # Deferred first or repeated cancellation during cleanup/publication
            # becomes FAIL after custody is finished, including actual child0.
            if cancelled_result():
                blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                try:write_result()
                finally:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
            if error is not None:raise error
            require(self.state.get('cleanup_completed') is True,'cleanup not complete')
            phase='returning';result=public_result(self.state)
            if cancelled_result():write_result();raise error
            return result
        except BaseException as e:
            self.remember_failure(e);self.state.update(status='FAIL',failure_code='deadline' if isinstance(e,Deadline) else self.state.get('failure_code','stage_failed'))
            if not isinstance(e,KeyboardInterrupt):write_result()
            if isinstance(e,KeyboardInterrupt):
                if received is None:received=getattr(e,'signum',signal.SIGINT)
                cancelled_result()
                blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                try:write_result()
                finally:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
            raise
        finally:
            try:
                for signum,handler in previous.items():signal.signal(signum,handler)
            except KeyboardInterrupt as late:
                received=getattr(late,'signum',signal.SIGINT);cancelled_result();blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                try:
                    write_result()
                    for signum,handler in previous.items():signal.signal(signum,handler)
                finally:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
                raise

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('action',choices=['validate','run']);p.add_argument('--admission',required=True);p.add_argument('--sha256',required=True);p.add_argument('--app-source');p.add_argument('--controller-source');p.add_argument('--private-root');p.add_argument('--public-root');args=p.parse_args(argv)
    try:
        a=read_admission(args.admission,args.sha256)
        if args.action=='validate':print('explicit hosted admission is valid; no action executed');return 0
        require(all((args.app_source,args.controller_source,args.private_root,args.public_root)),'explicit isolated source/output paths required')
        c=Coordinator(a,args.app_source,args.controller_source,args.private_root,args.public_root);c.state['admission_sha256']=args.sha256;c.pins[str(Path(args.admission).resolve())]=args.sha256;c.execute();return 0
    except (Exception,KeyboardInterrupt):
        # No arbitrary exception or child output crosses the public boundary.
        print('hosted forward refused or failed; inspect private evidence in the active ephemeral runner',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
