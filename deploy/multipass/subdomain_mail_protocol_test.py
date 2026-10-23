"""Execute the real canary CLI against a pinned-Stalwart keyword model."""
import contextlib,email,email.policy,hashlib,io,json,runpy,time,unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT=Path(__file__).with_name('subdomain-mail-protocol.py')
TOKEN='submail-protocol-test'
ACCOUNT=dict(address='preserve@parent.test',domain='parent.test',password='PRIVATE_PASSWORD_SENTINEL')

class Protocol(unittest.TestCase):
 def setUp(self):
  self.raw=None;self.uid=b'41';self.submissions=0;self.searches=[];self.readonly=[];self.fetches=[];self.corrupt=None;self.now=0
 def run_probe(self,mode,expected=None):
  owner=self
  class IMAP:
   def __init__(self,*args,**kwargs):pass
   def login(self,*args):return 'OK',[]
   def select(self,folder,readonly=False):owner.readonly.append(readonly);return 'OK',[b'1' if owner.raw else b'0']
   def uid(self,command,*args):
    if command.lower()=='search':
     if args== (None,'ALL'):return 'OK',[owner.uid if owner.raw else b'']
     value=args[-1].strip('"');owner.searches.append(value)
     # Pinned Stalwart0.11.8 indexes mail-parser's bracket-free Message-ID
     # as an exact keyword and passes the search value through unchanged.
     indexed=str(email.message_from_bytes(owner.raw)['Message-ID'])[1:-1] if owner.raw else None
     return 'OK',[owner.uid if value==indexed else b'']
    owner.fetches.append(args)
    raw=owner.raw
    if owner.corrupt=='wrong-id':raw=raw.replace(b'Message-ID: <',b'Message-ID: <other-')
    if owner.corrupt=='duplicate-id':raw=b'Message-ID: <foreign@parent.test>\r\n'+raw
    return 'OK',[(b'41 (BODY[])',raw)]
   def logout(self):return 'BYE',[]
   def shutdown(self):pass
  class SMTP:
   def __init__(self,*args,**kwargs):pass
   def __enter__(self):return self
   def __exit__(self,*args):pass
   def login(self,*args):return 235,b'ok'
   def send_message(self,message):
    owner.submissions+=1
    owner.raw=b'Received: synthetic local delivery\r\n'+message.as_bytes(policy=email.policy.SMTP)
    return {}
  def monotonic():owner.now+=31;return owner.now
  state=dict(token=TOKEN,mode=mode,accounts=[ACCOUNT],expected=expected)
  output=io.StringIO()
  with patch('sys.stdin',io.StringIO(json.dumps(state))),contextlib.redirect_stdout(output),patch('imaplib.IMAP4_SSL',IMAP),patch('smtplib.SMTP_SSL',SMTP),patch('ssl.create_default_context'),patch('subprocess.check_output',return_value='mail.owned.test\n'),patch('time.monotonic',side_effect=monotonic),patch('time.sleep'):
   runpy.run_path(str(SCRIPT),run_name='__main__')
  self.assertNotIn(ACCOUNT['password'],output.getvalue())
  return json.loads(output.getvalue())
 def test_seed_finds_normalized_keyword_and_keeps_exact_wire_identity(self):
  proof=self.run_probe('seed')
  self.assertEqual(self.submissions,1)
  self.assertEqual(self.searches[-1],proof[0]['message_id'][1:-1])
  self.assertEqual(proof[0]['sha256'],hashlib.sha256(self.raw).hexdigest())
  self.assertEqual(proof[0]['uid'],'41')
  self.assertTrue(all(self.readonly),'canary reads must not mutate flags')
  self.assertTrue(all(x[1]=='(BODY.PEEK[])' for x in self.fetches))
  self.assertEqual(str(email.message_from_bytes(self.raw)['Message-ID']),proof[0]['message_id'])
 def test_verify_never_resubmits_or_replaces_original_baseline(self):
  proof=self.run_probe('seed');self.assertEqual(self.run_probe('verify',proof),proof)
  self.assertEqual(self.submissions,1)
  self.raw+=b'changed bytes'
  with self.assertRaisesRegex(AssertionError,'bytes or UID changed'):self.run_probe('verify',proof)
 def test_changed_uid_rejected(self):
  proof=self.run_probe('seed');self.uid=b'42'
  with self.assertRaisesRegex(AssertionError,'bytes or UID changed'):self.run_probe('verify',proof)
 def test_wrong_or_duplicate_fetched_message_id_rejected(self):
  proof=self.run_probe('seed')
  for mode in ('wrong-id','duplicate-id'):
   with self.subTest(mode=mode):
    self.corrupt=mode
    with self.assertRaisesRegex(AssertionError,'message identity'):self.run_probe('verify',proof)
 def test_missing_message_fails_with_bounded_nonsecret_context(self):
  with self.assertRaisesRegex(AssertionError,'account_index=0.*inbox_messages=0') as error:
   self.run_probe('verify',[dict(message_id='<missing@'+TOKEN+'.test>',uid='41',sha256='0'*64)])
  self.assertNotIn(ACCOUNT['password'],str(error.exception));self.assertEqual(self.submissions,0)

if __name__=='__main__':unittest.main()
