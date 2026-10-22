#!/usr/bin/env python3
"""Actual local-only TLS canaries on an ownership-checked disposable guest."""
import email.message,hashlib,imaplib,json,secrets,smtplib,ssl,subprocess,sys,time
state=json.load(sys.stdin)
assert state['mode'] in ('seed','verify','denied')
assert state['token'].startswith('submail-') and all(c.isalnum() or c=='-' for c in state['token'])
host=subprocess.check_output(['hostname','-f'],text=True).strip()
context=ssl.create_default_context(cafile='/etc/stalwart/tls/cert.pem')
proof=[]
for index,account in enumerate(state['accounts']):
 assert account['address'].endswith('@'+account['domain']) and account['domain'].endswith('.test')
 client=imaplib.IMAP4_SSL(host,993,ssl_context=context,timeout=15)
 try:
  try:client.login(account['address'],account['password'])
  except imaplib.IMAP4.error:
   if state['mode']=='denied':proof.append({'denied':True});continue
   raise
  assert state['mode']!='denied','disabled account authenticated'
  if state['mode']=='seed':
   message=email.message.EmailMessage();message['From']=account['address'];message['To']=account['address']
   message['Message-ID']='<'+secrets.token_hex(16)+'@'+state['token']+'.test>'
   message['Subject']='Nakpanel preservation '+state['token'];message.set_content('Synthetic preservation canary '+secrets.token_hex(24))
   with smtplib.SMTP_SSL(host,465,context=context,timeout=15) as smtp:
    smtp.login(account['address'],account['password']);smtp.send_message(message)
   message_id=message['Message-ID']
  else:message_id=state['expected'][index]['message_id']
  deadline=time.monotonic()+90
  while True:
   status,_=client.select('INBOX');assert status=='OK'
   status,items=client.uid('search',None,'HEADER','Message-ID','"'+message_id+'"')
   if status=='OK' and items[0]:break
   assert time.monotonic()<deadline,'preserved message missing';time.sleep(2)
  uid=items[0].split();assert len(uid)==1,'ambiguous preservation canary'
  status,body=client.uid('fetch',uid[0],'(BODY.PEEK[])');assert status=='OK'
  raw=b''.join(x[1] for x in body if isinstance(x,tuple))
  item=dict(message_id=message_id,uid=uid[0].decode(),sha256=hashlib.sha256(raw).hexdigest())
  if state['mode']=='verify':assert item==state['expected'][index],'preserved message bytes or UID changed'
  proof.append(item)
 finally:
  try:client.logout()
  except (OSError,imaplib.IMAP4.error):client.shutdown()
print(json.dumps(proof))
