from __future__ import annotations

import base64
import errno
import fnmatch
import json
import posixpath
import stat
import time
import zipfile
from pathlib import Path

from .transfers import MAX_FILES, MAX_TRANSFER_BYTES, zip_members


def resolve_path(sftp, path, cwd='.'):
    home=sftp.normalize('.')
    if path == '~': path=home
    elif path.startswith('~/'): path=posixpath.join(home,path[2:])
    if not path.startswith('/'):
        base=home if cwd in {'.','~'} else posixpath.join(home,cwd[2:]) if cwd.startswith('~/') else cwd
        path=posixpath.join(base,path)
    return posixpath.normpath(path)


def attributes(path, a):
    mode=a.st_mode or 0
    return {'path':path,'name':posixpath.basename(path), 'type':'directory' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode) else 'special',
            'size_bytes':a.st_size, 'mtime':a.st_mtime, 'mode':oct(stat.S_IMODE(mode)), 'uid':a.st_uid,'gid':a.st_gid}


def operation(sftp, payload, store, stop, progress):
    args=json.loads(payload.arguments); kind=payload.operation
    path=resolve_path(sftp,args.get('path',payload.cwd),payload.cwd)
    deadline=time.monotonic()+payload.timeout_seconds
    def check():
        if stop.is_set(): raise InterruptedError('已终止 SFTP 操作')
        if time.monotonic() > deadline: raise TimeoutError('SFTP 操作超过执行时限')
    def entries(directory):
        for a in sftp.listdir_iter(directory,read_aheads=2):
            check()
            if a.filename in {'.','..'} or '/' in a.filename or '\x00' in a.filename: continue
            yield a
    def walk(root,depth_limit=16):
        pending=[(root,0)]; visited=0
        while pending:
            directory,depth=pending.pop()
            for a in entries(directory):
                visited+=1
                if visited > MAX_FILES: raise ValueError('扫描达到 5000 项上限，请缩小根目录')
                full=posixpath.join(directory,a.filename)
                yield full,a
                if stat.S_ISDIR(a.st_mode or 0) and depth < depth_limit: pending.append((full,depth+1))
    progress(phase='executing',progress_bytes=0)
    if kind == 'list_directory':
        rows=[]; offset=args.get('offset',0); limit=args.get('limit',200); count=0
        for a in entries(path):
            if count >= offset and len(rows) < limit: rows.append(attributes(posixpath.join(path,a.filename),a))
            count+=1
            if len(rows)==limit: break
        # Directory offsets use SFTP enumeration order, not a persistent snapshot.
        return {'path':path,'entries':rows,'offset':offset,'next_offset':offset+len(rows),'has_more':len(rows)==limit,'snapshot':False}
    if kind == 'stat_path':
        a=sftp.lstat(path)
        return attributes(path,a)
    if kind == 'read_file':
        a=sftp.stat(path)
        if not stat.S_ISREG(a.st_mode or 0): raise ValueError('只允许读取普通文件')
        offset=args.get('offset',0); limit=args.get('limit',16384)
        with sftp.open(path,'rb') as source: source.seek(offset); data=source.read(limit)
        check()
        return {'path':path,'offset':offset,'next_offset':offset+len(data),'eof':offset+len(data)>=a.st_size,
                'size_bytes':a.st_size,'text':data.decode('utf-8',errors='replace'),'data_base64':base64.b64encode(data).decode('ascii')}
    if kind == 'find_files':
        root=sftp.normalize(path)
        rows=[]; truncated=False
        for full,a in walk(root,args.get('max_depth',8)):
            if fnmatch.fnmatchcase(a.filename,args['pattern']):
                rows.append(attributes(full,a))
                if len(rows)>=args.get('limit',100): truncated=True; break
        return {'root':root,'matches':rows,'truncated':truncated,'follow_symlinks':False}
    if kind == 'test_connection':
        progress(phase='checking_default_cwd')
        a=sftp.stat(path)
        if not stat.S_ISDIR(a.st_mode or 0): raise ValueError('默认工作目录不是目录')
        result={'default_cwd':sftp.normalize(path),'default_cwd_exists':True,'ssh_authenticated':True,'sftp_available':True}
        for remote,label in [('/etc/os-release','os_release'),('/etc/hostname','hostname')]:
            try:
                with sftp.open(remote,'rb') as source: result[label]=source.read(4096).decode('utf-8',errors='replace').strip()
            except OSError: result[label]=''
        return result
    if kind in {'download_file','download_directory'}:
        tid=args['transfer_id']; local=store.path(tid); total=0
        def copy(source,out,expected):
            nonlocal total
            if expected > MAX_TRANSFER_BYTES-total: raise ValueError('下载超过 64 MiB 上限')
            while True:
                check(); data=source.read(65536)
                if not data: break
                total+=len(data)
                if total > MAX_TRANSFER_BYTES: raise ValueError('下载超过 64 MiB 上限')
                out.write(data); progress(progress_bytes=total)
        try:
            if kind == 'download_file':
                a=sftp.stat(path)
                if not stat.S_ISREG(a.st_mode or 0): raise ValueError('下载目标必须是普通文件')
                progress(total_bytes=a.st_size)
                with sftp.open(path,'rb') as source,local.open('wb') as out: copy(source,out,a.st_size)
            else:
                root=sftp.normalize(path)
                if not stat.S_ISDIR(sftp.stat(root).st_mode or 0): raise ValueError('打包目标必须是目录')
                skipped=0
                with zipfile.ZipFile(local,'w',compression=zipfile.ZIP_DEFLATED,allowZip64=False) as archive:
                    for full,a in walk(root,32):
                        relative=posixpath.relpath(full,root)
                        if stat.S_ISREG(a.st_mode or 0):
                            with sftp.open(full,'rb') as source,archive.open(relative,'w') as out: copy(source,out,a.st_size)
                        elif stat.S_ISDIR(a.st_mode or 0): archive.writestr(relative+'/',b'')
                        else: skipped+=1
            result=store.finish_download(tid)
            if kind == 'download_directory': result['skipped_links_or_special_files']=skipped
            return result
        except BaseException:
            store.remove(tid,force=True); raise
    if kind in {'upload_file','upload_directory'}:
        tid=args['transfer_id']; local=store.path(tid,complete=True); info=store.info(tid)
        if store._hash(local)!=info['sha256']: raise ValueError('上传缓存被修改，拒绝执行')
        def write_file(remote,source,size,overwrite=False):
            check(); parent=posixpath.dirname(remote)
            # Resolve the parent and reject a destination link. Commit through rename.
            actual_parent=sftp.normalize(parent)
            if actual_parent != parent: raise ValueError('上传目标父目录包含符号链接，需改用真实路径')
            existing=None
            try: existing=sftp.lstat(remote)
            except OSError as exc:
                if exc.errno != errno.ENOENT: raise
            if existing and (not overwrite or not stat.S_ISREG(existing.st_mode or 0)):
                raise ValueError('目标已存在或不是普通文件；覆盖必须显式选择')
            temporary=posixpath.join(parent,'.wassh-'+tid+'.part')
            moved=False
            try:
                with sftp.open(temporary,'wx') as out:
                    sftp.chmod(temporary,stat.S_IMODE(existing.st_mode) if existing else 0o600)
                    count=0
                    while True:
                        check(); data=source.read(65536)
                        if not data: break
                        out.write(data); count+=len(data); progress(progress_bytes=count,total_bytes=size)
                    out.flush()
                check()
                if existing: sftp.posix_rename(temporary,remote)
                else: sftp.rename(temporary,remote)
                moved=True
                return count
            finally:
                if not moved:
                    try: sftp.remove(temporary)
                    except OSError: pass
        if kind == 'upload_file':
            with local.open('rb') as source: written=write_file(path,source,info['size_bytes'],args.get('overwrite',False))
            return {'path':path,'size_bytes':written,'sha256':info['sha256'],'overwrite':args.get('overwrite',False)}
        members=zip_members(local)
        if sftp.normalize(posixpath.dirname(path)) != posixpath.dirname(path): raise ValueError('目标父目录含符号链接，请使用真实路径')
        # New destination only. No archive may replace an existing directory.
        sftp.mkdir(path,mode=0o700)
        completed=[]; dirs={path}
        try:
            with zipfile.ZipFile(local) as archive:
                for name,size,is_dir in sorted(members,key=lambda m:(len(m[0].split('/')),m[0])):
                    check(); full=posixpath.join(path,name.rstrip('/')); parent=posixpath.dirname(full)
                    components=posixpath.relpath(parent,path).split('/') if parent!=path else []
                    here=path
                    for component in components:
                        here=posixpath.join(here,component)
                        if here not in dirs: sftp.mkdir(here,mode=0o700); dirs.add(here)
                    if is_dir:
                        if full not in dirs: sftp.mkdir(full,mode=0o700); dirs.add(full)
                    else:
                        with archive.open(name) as source: write_file(full,source,size)
                        completed.append(name)
            return {'path':path,'files_written':len(completed),'complete':True,'archive_sha256':info['sha256']}
        except BaseException as exc:
            raise RuntimeError(f'目录上传未完成；新目录 {path} 保留了 {len(completed)} 个已完成文件：{exc}') from exc
    if kind in {'create_session','update_session'}:
        a=sftp.stat(path)
        if not stat.S_ISDIR(a.st_mode or 0): raise ValueError('会话目录不存在或不是目录')
        return {'cwd':sftp.normalize(path)}
    raise ValueError('不支持此文件操作')
