"""Guard the real protocol fixture and required-runtime acceptance gate locally."""
import importlib.util,json,smtplib,socketserver,tempfile,threading,unittest
from pathlib import Path

def module(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

acceptance=module('operations_acceptance','operations-verify.py')
smtp=module('operations_smtp','operations-smtp-capture.py')

class OperationsGuards(unittest.TestCase):
 def test_missing_hosting_runtime_or_extension_fails(self):
  for minor in ('8.3','8.4','8.5'):
   with self.subTest(minor=minor):
    acceptance.require_php(minor+'.1',['curl','Zend OPcache'],'curl\nZend OPcache\n',minor,['curl','Zend OPcache'])
    with self.assertRaises(ValueError):acceptance.require_php('8.5.1',['curl'],'curl',minor,['curl','imagick'])
    with self.assertRaises(ValueError):acceptance.require_php(minor+'.1',['curl','imagick'],'curl',minor,['curl','imagick'])
 def test_loopback_fixture_rejects_data_then_accepts_before_quit_disconnect(self):
  with tempfile.TemporaryDirectory() as directory:
   state=Path(directory);(state/'mode').write_text('reject')
   with socketserver.TCPServer(('127.0.0.1',0),smtp.Capture) as server:
    server.state=state;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
     client=smtplib.SMTP(*server.server_address,timeout=3)
     with self.assertRaises(smtplib.SMTPDataError):client.sendmail('panel@operations.test',['admin@nakpanel.test'],'Subject: owned fixture\n\nbody')
     client.close();(state/'mode').write_text('accept')
     client=smtplib.SMTP(*server.server_address,timeout=3)
     client.sendmail('panel@operations.test',['admin@nakpanel.test'],'Subject: owned fixture\n\nbody')
     with self.assertRaises(smtplib.SMTPServerDisconnected):client.quit()
     rows=[json.loads(line) for line in (state/'receipts.jsonl').read_text().splitlines()]
     self.assertEqual([r['accepted'] for r in rows],[False,True]);self.assertNotIn('body',rows[0])
    finally:server.shutdown();thread.join(3)

if __name__=='__main__':unittest.main()
