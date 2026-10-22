import importlib.util,os,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('submail',Path(__file__).with_name('subdomain-mail-verify.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Guards(unittest.TestCase):
 def test_hosted_guard_rejects_local_even_with_github_flag(self):
  with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted'},clear=True):
   with self.assertRaises(ValueError):m.hosted_guard()
 def test_archive_rejects_links_and_parent_escape_before_extract(self):
  for name,kind in [('../escape',tarfile.REGTYPE),('bundle/link',tarfile.SYMTYPE)]:
   with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
    root=Path(temp); archive=root/'bundle.tar'
    with tarfile.open(archive,'w') as stream:
     item=tarfile.TarInfo(name);item.type=kind;item.linkname='/tmp/foreign';stream.addfile(item)
    with self.assertRaises(ValueError):m.extract_release(archive,root/'out')
    self.assertFalse((root/'out').exists())
 def test_identity_rejects_wrong_commit_and_architecture(self):
  valid={'commit':'a'*40,'architecture':'amd64','development':True}
  with self.assertRaises(ValueError):m.check_identity(valid,'b'*40)
  with self.assertRaises(ValueError):m.check_identity(dict(valid,architecture='arm64'),'a'*40)

class AcceptanceOrder(unittest.TestCase):
 class Accepted(Exception):pass
 def harness(self,root,corrupt=None,bypass=False):
  from types import SimpleNamespace
  f=m.Drill.__new__(m.Drill)
  f.token='submail-owned-test';f.vm='nakpanel-owned-test';f.private=root;f.env={'NAKPANEL_REMOTE_SRC':'/owned/source'};f.state={'checks':[]}
  f.evidence=root;self.lost=False;self.mutated=False;self.mailboxes=3
  def stage(name):
   if name=='disable-suspend-reactivate':raise self.Accepted()
  f.stage=stage
  f.shell=lambda *args:'192.0.2.1'
  f.wait=lambda *args:None
  f.ready=lambda *args:None
  def db(query):
   if 'quota_mb' in query:return '64'
   if 'count(*) FROM mailboxes' in query:return str(self.mailboxes)
   if 'shop.current' in query:return '2'
   if 'news.current' in query:return '3'
   if 'foreign-submail' in query:return '4'
   if 'customers WHERE email' in query:return '5'
   if 'subscriptions WHERE customer_id' in query:return '6'
   return '1'
  f.db=db
  f.post=lambda *args,**kwargs:None
  def mail(site,*args,**kwargs):
   if site==2:
    self.lost=corrupt=='message';self.mutated=corrupt=='resource'
   return site*10
  f.mail=mail
  f.account=lambda domain,sub,address:dict(address='preserve@'+address,password='fixture',domain=address)
  f.guest=lambda *args,**kwargs:'ubuntu:26.04:resolute' if args[0]=='bash' else (args[1].removeprefix('/usr/bin/php')+'.1' if args[0]=='sudo' and args[1].startswith('/usr/bin/php') else 'active')
  def cmd(args,**kwargs):
   if args[0]=='node':
    (root/'child-mail.json').write_text(m.json.dumps(dict(address='child@shop.current-bootstrap.test',password='fixture',domain='shop.current-bootstrap.test')))
   return ''
  f.cmd=cmd
  def protocol(mode,accounts,expected=None):
   if mode=='seed':return [{'message':'replacement' if self.lost else 'original'} for a in accounts]
   m.require(not self.lost or all(x['message']=='replacement' for x in expected),'prior message lost')
   return expected
  f.protocol=protocol
  f.canaries=lambda *args:'changed' if self.mutated else 'original'
  def passed(name):
   if not bypass:raise self.Accepted()
  f.passed=passed
  owner=self
  class HTTP:
   def __init__(self,base):self.base=base
   def login(self,*args):pass
   def request(self,path,fields=None,ok=(200,202,303)):
    code=200
    if fields is None and path.startswith('/sites/'):code=404
    if fields is not None and path.endswith('/mailboxes'):
     if fields['local_part']=='forbidden':code=400 if owner.mailboxes>=4 else 303
     elif fields['local_part']=='over-limit':code=400
     else:owner.mailboxes+=1;code=303
    if fields is not None and path.endswith('/mail-aliases'):
     code=400 if fields['local_part']=='over-limit' else 303
    m.require(code in ok,'foreign ownership bypass accepted with spare capacity')
    return code,b'{}'
  return f,HTTP
 def test_child_corruption_cannot_become_new_preservation_baseline(self):
  for kind in ('message','resource'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
    f,http=self.harness(Path(temp),corrupt=kind)
    accepted=False
    with patch.object(m,'HTTP',http):
     try:f.run()
     except self.Accepted:accepted=True
     except ValueError:pass
    self.assertFalse(accepted,'initial child corruption became the accepted baseline')
 def test_foreign_write_bypass_is_detected_with_capacity_available(self):
  with tempfile.TemporaryDirectory() as temp:
   f,http=self.harness(Path(temp),bypass=True);accepted=False
   with patch.object(m,'HTTP',http):
    try:f.run()
    except self.Accepted:accepted=True
    except ValueError:pass
   self.assertFalse(accepted,'quota exhaustion masked broken foreign ownership enforcement')

if __name__=='__main__':unittest.main()
