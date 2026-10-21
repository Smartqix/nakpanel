"""Fixed safe projection from the current sealed coordinator invocation only."""
import hashlib,json,os,stat
from pathlib import Path
from l3 import *

def project(root,expected,state=None):
 root=physical_dir(root);context=decode(regular(root/'run-context.json').read_bytes());s=root.lstat()
 need(type(expected) is dict and context.get('run_id')==expected.get('run_id') and context.get('controller_commit')==expected.get('controller_commit') and context.get('source_commit')==SOURCE and context.get('roles')==roles(expected['run_id']) and context.get('root_identity')==[s.st_dev,s.st_ino],'IDENTITY')
 if state is None:state=decode(regular(root/'private-result.json',max_bytes=8*1024*1024).read_bytes())
 need(type(state) is dict and state.get('context_sha256')==sha(root/'run-context.json'),'IDENTITY')
 rows=state.get('custody');need(type(rows) is list and len(rows)<=500,'IDENTITY')
 for ref in rows:
  need(type(ref) is dict and set(ref)=={'phase','sha256'} and type(ref['phase']) is str and re.fullmatch(r'a[0-9]{3,5}-(?:host|source|target)',ref['phase']) and SHA.fullmatch(ref['sha256']),'IDENTITY');p=root/'logs'/ref['phase']/'receipt.json';need(sha(regular(p))==ref['sha256'],'IDENTITY');r=decode(p.read_bytes());b=r.get('binding');need(type(b) is dict and b.get('run_id')==context['run_id'] and b.get('source_commit')==SOURCE,'IDENTITY')
  role=b.get('role');need(role in ('host','source','target'),'IDENTITY');identity=context['roles']['source' if role=='host' else role];need(b.get('vm')==identity['vm'] and b.get('token')==identity['token'],'IDENTITY')
  if state.get('overall')=='PASS':need(r.get('status')=='PASS' and r.get('process_group_empty') is True and r.get('process_exited') is True and r.get('exit_code')==0,'IDENTITY')
  for field,name in (('stdout','stdout.log'),('stderr','stderr.log')):
   proof=r.get(field);log=regular(p.parent/name,max_bytes=64*1024*1024);need(type(proof) is dict and proof.get('bytes')==log.stat().st_size and proof.get('sha256')==sha(log),'IDENTITY')
 if state.get('overall')=='PASS':need([p.get('phase') for p in state.get('phases',[]) if p.get('status')=='PASS']==list(PHASES) and rows,'IDENTITY')
 return safe_result(state,failure_root=root)
