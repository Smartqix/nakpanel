"""Fixed source26 diagnostic contracts. Data is not admission authority."""
import hashlib,json,os,re,stat
from pathlib import Path
SOURCE='6378b0ae9d15f17481b080926af7fb0bf0761724'
QUALIFIER='8612b11f485ba2d4c4e6051704ab822dc1de9f5c'
HELPER='350bd20c6e64d609a53feda0e513e396f4f62267325bac076a7a50d037899b0c'
MODE='SAME_VERSION_REINSTALL_AND_FAILED_CONFIGURATION_RECOVERY'
PUBLIC_RELATIVES={'cell/report.json','cell/release-manifest.json','cell/roundcube-send-read.json','cell/roundcube-send-read.execution.json','cell/sury-maintenance-request.json'}|{'cell/sury-maintenance/'+x for x in ('preparation.json','capacity.json','roundcube_execution_receipt.json','retention_receipt.json','native_gpgv_receipt.json','package-baseline.json','package-layout.json','result.json','recovery.json','reboot-1.json','reboot-2.json','roundcube-recovered.execution.json','roundcube-reboot-1.execution.json','roundcube-reboot-2.execution.json')}
FILES=('spec.json','drill/result.json','drill/stage-stage.stdout','drill/stage-stage.stderr','drill/run-stage.stdout','drill/run-stage.stderr','controller.log','drill/diagnostic-run.json','drill/diagnostic-stage.json','early-preparation.json')
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
def context(value):
    keys={'schema','run_id','run_attempt','wrapper_commit','source_vm','run_token','runtime_commit','qualifier_commit','maintenance_helper_sha256'}
    need(type(value) is dict and set(value)==keys and value['schema']=='source26-diagnostic-context-v1')
    need(type(value['run_id']) is int and 0<value['run_id']<10**14 and type(value['run_attempt']) is int and 0<value['run_attempt']<100)
    need(type(value['wrapper_commit']) is str and re.fullmatch('[0-9a-f]{40}',value['wrapper_commit']))
    token='hosted-'+str(value['run_id'])+'-'+str(value['run_attempt'])+'-26-04'
    need(value['run_token']==token and value['source_vm']=='nakpanel-26-04-amd64-'+token)
    need(value['runtime_commit']==SOURCE and value['qualifier_commit']==QUALIFIER and value['maintenance_helper_sha256']==HELPER)
    return dict(value)
def meta(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def directory(path):
    path=Path(path);need(path.is_absolute() and path.resolve()==path)
    info=path.lstat();need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.getuid())
    return info
def root_identity(root):
    info=directory(root);return [info.st_dev,info.st_ino]
def read_private(root,relative,limit=65536):
    root=Path(root);before=directory(root);need(relative in FILES or relative in PUBLIC_RELATIVES or relative in ('report.json','canonical-execution.json','runtime-binding.json','receipt.json'))
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
    except (OSError,ValueError):raise Rejected() from None
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
