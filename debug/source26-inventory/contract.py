"""Explicit inventory-only contracts; no canonical or M admission authority."""
import hashlib,json,os,re,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE='1627bba3c681a884255eb91452dbba74a43ebbdc'
HELPER='87d2a6f05e6d4ebfa72f960a2a067eb552455c54ba168058204a03fa28f26e8e'
PREPARE='180c2da2874de86b2e03741e334a7faba80c7afb080089d12d38117624e32614'
SCOPE='SOURCE26_FRESH_INSTALL_INVENTORY_ONLY'
BRANCH='ricky/sury-source26-inventory-only-v2'
MODE='SAME_VERSION_REINSTALL_AND_FAILED_CONFIGURATION_RECOVERY'
PRIVATE_FILES={'context.json','state.json','receipt.json','result.json','observation.json','identity.json','runtime-binding.json','install/receipt.json','inventory/receipt.json','cleanup/receipt.json'}
class Rejected(ValueError):
    def __init__(self):super().__init__('source26 diagnostic rejected')
def need(value):
    if not value:raise Rejected()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def pairs(items):
    value={}
    for key,item in items:
        need(key not in value);value[key]=item
    return value
def parse(raw):
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(Rejected()))
    except Exception:raise Rejected() from None
def make_context(run_id,wrapper):
    token='hosted-inventory-'+str(run_id)+'-1-26-04'
    return context(dict(schema='source26-inventory-context-v1',scope=SCOPE,run_id=run_id,run_attempt=1,wrapper_commit=wrapper,source_commit=SOURCE,source_vm='nakpanel-26-04-amd64-'+token,run_token=token,profile='ubuntu-26.04-sury',php_provider='sury',architecture='amd64',manifest_sha256=PINS['runtime_sources']['candidate']['manifest_sha256'],installed_binary_sha256=PINS['runtime_sources']['candidate']['installed_binary_sha256']))
def context(value):
    keys={'schema','scope','run_id','run_attempt','wrapper_commit','source_commit','source_vm','run_token','profile','php_provider','architecture','manifest_sha256','installed_binary_sha256'}
    need(type(value) is dict and set(value)==keys and value['schema']=='source26-inventory-context-v1' and value['scope']==SCOPE)
    need(type(value['run_id']) is int and 0<value['run_id']<10**14 and type(value['run_attempt']) is int and value['run_attempt']==1)
    need(type(value['wrapper_commit']) is str and re.fullmatch('[a-f0-9]{40}',value['wrapper_commit']))
    token='hosted-inventory-'+str(value['run_id'])+'-1-26-04'
    need(value['run_token']==token and value['source_vm']=='nakpanel-26-04-amd64-'+token and len(token)<=63)
    need(value['source_commit']==SOURCE and value['profile']=='ubuntu-26.04-sury' and value['php_provider']=='sury' and value['architecture']=='amd64')
    need(value['manifest_sha256']==PINS['runtime_sources']['candidate']['manifest_sha256'] and value['installed_binary_sha256']==PINS['runtime_sources']['candidate']['installed_binary_sha256'])
    return dict(value,installed_binary_sha256=dict(value['installed_binary_sha256']))
def meta(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def directory(path):
    path=Path(path);need(path.is_absolute() and path.resolve()==path)
    info=path.lstat();need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.getuid())
    return info
def root_identity(root):
    info=directory(root);return [info.st_dev,info.st_ino]
def read_private(root,relative,limit=65536):
    root=Path(root);before=directory(root);need(relative in PRIVATE_FILES)
    path=root/relative;parents=[root]
    for part in Path(relative).parts[:-1]:parents.append(parents[-1]/part)
    seals=[]
    for parent in parents:seals.append((parent,meta(directory(parent))))
    fd=None
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid() and info.st_nlink==1 and info.st_size<=limit)
        expected=meta(info);need(meta(path.lstat())==expected)
        data=bytearray()
        while len(data)<=limit:
            block=os.read(fd,min(65536,limit+1-len(data)))
            if not block:break
            data.extend(block)
        need(len(data)<=limit and len(data)==info.st_size and meta(os.fstat(fd))==expected and meta(path.lstat())==expected)
        for parent,seal in seals:need(meta(parent.lstat())==seal)
        return bytes(data),seals+[(path,expected)]
    except ValueError:raise Rejected() from None
    finally:
        if fd is not None:os.close(fd)
def stable(seals):
    try:return all(meta(p.lstat())==value for p,value in seals)
    except OSError:return False
def exclusive_output(path,value):
    return exclusive_bytes(path,canonical(value))
def exclusive_bytes(path,raw):
    path=Path(path);parent=directory(path.parent);fd=None
    try:
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        seal=meta(os.fstat(fd));need(type(raw) is bytes and len(raw)<=2**20)
        offset=0
        while offset<len(raw):
            wrote=os.write(fd,raw[offset:]);need(wrote>0);offset+=wrote
        os.fsync(fd)
        need(meta(path.lstat())==meta(os.fstat(fd)) and root_identity(path.parent)==[parent.st_dev,parent.st_ino])
        return fd
    except Exception:
        if fd is not None:os.close(fd)
        raise Rejected() from None

PINS=parse((HERE/'bootstrap-pins.json').read_bytes())
def code_pins():return parse((HERE/'runtime-code-pins.json').read_bytes())
def validate_runtime_files():
    pins=code_pins();need(type(pins) is dict and set(pins)=={'contract.py','custody.py','custody_base.py','observer.py','driver.py','projector.py','bootstrap.py','artifact_support.py','bootstrap-pins.json','runtime-binding.json','inventory_ast'})
    for name,expected in pins.items():
        need(type(name) is str and Path(name).name==name and type(expected) is str and re.fullmatch('[a-f0-9]{64}',expected))
        if name=='inventory_ast':continue
        path=HERE/name;need(path.resolve()==path and digest(path.read_bytes())==expected)
    return pins
def pinned_source(path,expected):
    path=Path(path);need(path.is_absolute() and path.resolve()==path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022 and info.st_nlink==1 and info.st_size<=256*1024)
        raw=os.read(fd,256*1024+1);need(len(raw)==info.st_size and digest(raw)==expected)
        return raw
    finally:os.close(fd)
def safe_save(path,value):
    fd=exclusive_output(path,value);os.close(fd)
