"""Unchanged artifact authentication/materialization functions from reviewed v3."""
import hashlib,io,json,os,re,stat,subprocess,sys,tarfile,time,zipfile
from pathlib import Path,PurePosixPath
from urllib.request import Request,urlopen,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError
from contract import SOURCE,PINS,need,parse,digest,exclusive_bytes
class NoRedirect(HTTPRedirectHandler):

    def redirect_request(self, *args, **kwargs):
        return None

def urlopen_no_redirect(request, timeout):
    return build_opener(NoRedirect()).open(request, timeout=timeout)

def bounded_response(response, limit):
    data = bytearray()
    while len(data) <= limit:
        block = response.read(min(2 ** 20, limit + 1 - len(data)))
        if not block:
            break
        data.extend(block)
    need(len(data) <= limit)
    return bytes(data)

def api_json(path, token, *, evidence=None):
    need(path.startswith('/repos/Smartqix/nakpanel/actions/'))
    request = Request('https://api.github.com' + path, headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + token, 'X-GitHub-Api-Version': '2022-11-28'})
    with urlopen_no_redirect(request, timeout=60) as response:
        raw = bounded_response(response, 2 ** 20)
    if evidence is not None:
        fd = exclusive_bytes(evidence, raw)
        os.close(fd)
    return parse(raw)

def api_archive(url, token, limit):
    need(url == 'https://api.github.com/repos/Smartqix/nakpanel/actions/artifacts/12231269532/zip')
    request = Request(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
    try:
        with urlopen_no_redirect(request, timeout=60) as response:
            return bounded_response(response, limit)
    except HTTPError as error:
        need(error.code == 302)
        location = error.headers.get('Location', '')
        from urllib.parse import urlparse
        parsed = urlparse(location)
        need(parsed.scheme == 'https' and parsed.username is None and (parsed.password is None) and (parsed.port in (None, 443)) and parsed.hostname and (parsed.hostname.endswith('.blob.core.windows.net') or parsed.hostname.endswith('.githubusercontent.com')))
        with urlopen_no_redirect(Request(location), timeout=300) as response:
            return bounded_response(response, limit)

def command(argv, *, cwd, env, timeout=300):
    need(type(argv) is list and all((type(x) is str and '\x00' not in x for x in argv)))
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    need(result.returncode == 0)
    return result.stdout

def clean_child_environment(env):
    return {k: v for (k, v) in env.items() if not k.startswith(('PYTHON', 'NAKPANEL_', 'GIT_CONFIG')) and k not in ('__PYVENV_LAUNCHER__', 'BASH_ENV', 'ENV', 'CDPATH', 'GH_TOKEN', 'GITHUB_TOKEN')}

def check_archive_metadata(run, jobs, artifact):
    need(type(run) is dict and run.get('id') == 39347496239 and (type(run.get('id')) is int) and (run.get('run_attempt') == 1) and (type(run.get('run_attempt')) is int))
    need(run.get('event') == 'workflow_dispatch' and run.get('head_sha') == SOURCE and (run.get('head_branch') == 'ricky/ubuntu-26-sury-candidate26') and (run.get('path') == '.github/workflows/ubuntu-hosted-qualification.yml'))
    repository = run.get('repository', {})
    need(repository.get('id') == 1292416194 and type(repository.get('id')) is int and (repository.get('full_name') == 'Smartqix/nakpanel') and (repository.get('private') is False))
    need(type(jobs) is dict and type(jobs.get('jobs')) is list)
    chosen = [j for j in jobs['jobs'] if type(j) is dict and j.get('id') == 118383538478]
    need(len(chosen) == 1 and chosen[0].get('name') == 'signed-bundles' and (chosen[0].get('conclusion') == 'success'))
    need(type(artifact) is dict and type(artifact.get('id')) is int and (artifact['id'] == 12231269532) and (artifact.get('name') == PINS['artifact']['name']) and (artifact.get('expired') is False))
    need(type(artifact.get('size_in_bytes')) is int and artifact['size_in_bytes'] == 73997080 and (artifact.get('digest') == PINS['artifact']['digest']))
    origin = artifact.get('workflow_run', {})
    need(origin.get('id') == 39347496239 and type(origin.get('id')) is int and (origin.get('head_sha') == SOURCE))

def safe_member(name):
    path = PurePosixPath(name)
    need(name and (not path.is_absolute()) and ('..' not in path.parts) and ('\\' not in name) and ('\x00' not in name))
    return path
ZIP_NAMES = {'bundles.json', 'images.json', 'test-public.pem', 'candidate/nakpanel-29.0.0-linux-amd64.tar.gz', 'prior/nakpanel-29.0.0-linux-amd64.tar.gz', 'images/noble/SHA256SUMS', 'images/noble/SHA256SUMS.gpg', 'images/resolute/SHA256SUMS', 'images/resolute/SHA256SUMS.gpg'}

def extract_zip(raw, destination):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        entries = z.infolist()
        names = [x.filename for x in entries]
        need(len(names) == len(set(names)) and set(names) == ZIP_NAMES)
        need(sum((x.file_size for x in entries)) <= 80 * 2 ** 20)
        for x in entries:
            safe_member(x.filename)
            kind = x.external_attr >> 16 & 61440
            need(not x.is_dir() and kind in (0, stat.S_IFREG) and (x.file_size <= 40 * 2 ** 20))
        destination = Path(destination)
        destination.mkdir(mode=448)
        for x in entries:
            path = destination / x.filename
            path.parent.mkdir(mode=448, parents=True, exist_ok=True)
            with path.open('xb') as out:
                out.write(z.read(x))
            path.chmod(384)

def extract_tar(raw, destination):
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as t:
        entries = t.getmembers()
        names = [x.name for x in entries]
        need(len(entries) <= 300 and len(names) == len(set(names)) and (sum((x.size for x in entries)) <= 200 * 2 ** 20))
        for x in entries:
            safe_member(x.name)
            need((x.isdir() or x.isfile()) and (not (x.issym() or x.islnk() or x.isdev())))
        destination = Path(destination)
        destination.mkdir(mode=448)
        for x in entries:
            path = destination / x.name
            if x.isdir():
                path.mkdir(mode=448, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=448, parents=True, exist_ok=True)
                with path.open('xb') as out:
                    out.write(t.extractfile(x).read())
                path.chmod(448 if x.mode & 73 else 384)

def prepare_bundles(raw, destination, app, env):
    need(len(raw) == 73997080 and digest(raw) == PINS['artifact']['digest'].split(':')[1])
    extract_zip(raw, destination)
    need(parse((destination / 'bundles.json').read_bytes()) == PINS['bundles_metadata'] and parse((destination / 'images.json').read_bytes()) == PINS['images'])
    need(digest((destination / 'test-public.pem').read_bytes()) == PINS['public_key_sha256'])
    exports = {}
    for (tree, prefix) in (('candidate', 'NAKPANEL_RELEASE_'), ('prior', 'NAKPANEL_PRIOR_RELEASE_')):
        item = PINS['runtime_sources'][tree]
        archive = destination / item['archive']
        data = archive.read_bytes()
        need(len(data) == item['archive_bytes'] and digest(data) == item['archive_sha256'])
        unpack = destination / (tree + '-unpacked')
        extract_tar(data, unpack)
        bundle = unpack / PINS['bundles_metadata'][tree]['directory'].split('/', 1)[1]
        need(digest((bundle / 'manifest.json').read_bytes()) == item['manifest_sha256'])
        command([sys.executable, '-I', '-B', str(app / 'deploy/release/verify.py'), '--bundle', str(bundle), '--public-key', str(destination / 'test-public.pem'), '--version', '29.0.0', '--architecture', 'amd64', '--allow-development'], cwd=str(app), env=env)
        exports[prefix + 'BUNDLE'] = str(bundle)
        exports[prefix + 'PUBLIC_KEY'] = str(destination / 'test-public.pem')
        exports[prefix + 'VERSION'] = '29.0.0'
    return exports
