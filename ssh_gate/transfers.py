from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import threading
import uuid
import zipfile
from pathlib import Path, PurePosixPath

MAX_TRANSFER_BYTES = 64 * 1024 * 1024
MAX_CACHE_BYTES = 256 * 1024 * 1024
MAX_FILES = 5000


def safe_name(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 180 or name in {'.', '..'} or any(c in name for c in '/\\\x00\r\n:'):
        raise ValueError('文件名必须是一个有效的文件名，不包含路径')
    return name


def zip_members(path: Path):
    """Validate every member before any server write, including size and link checks."""
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_FILES or sum(m.file_size for m in members) > MAX_TRANSFER_BYTES:
            raise ValueError('ZIP 解压规模超过 5000 项 / 64 MiB 上限')
        seen=set()
        for member in members:
            name=member.filename
            parts=PurePosixPath(name).parts
            mode=member.external_attr >> 16
            if (not name or name.startswith('/') or '\\' in name or ':' in name or '\x00' in name or
                    any(p in {'.', '..'} for p in parts) or not parts or name.rstrip('/') in seen or
                    (mode & 0o170000) == 0o120000 or member.flag_bits & 1):
                raise ValueError('ZIP 包含不安全路径、重复项、符号链接或加密内容')
            seen.add(name.rstrip('/'))
        return [(m.filename, m.file_size, m.is_dir()) for m in members]


class TransferStore:
    """Opaque IDs only over MCP. No remote caller can choose a Windows path."""
    def __init__(self, root: Path):
        self.root=root/'transfers'
        self._items={}
        self._lock=threading.RLock()
        self._restore()

    def _restore(self):
        index=self.root/'index.json'
        if not index.is_file():
            if self.root.exists() and any(re.fullmatch('[0-9a-f]{32}',p.stem) for p in self.root.glob('*.data')):
                raise ValueError('传输缓存缺少索引；请先备份 transfers 目录后修复或清理')
            return
        try:
            if index.stat().st_size>200000: raise ValueError('传输索引过大')
            rows=json.loads(index.read_text(encoding='utf-8'))
            if not isinstance(rows,list) or len(rows)>100: raise ValueError('传输索引无效')
            for raw in rows:
                tid=raw.get('transfer_id','');name=safe_name(raw.get('file_name',''))
                if not re.fullmatch('[0-9a-f]{32}',tid) or raw.get('direction') not in {'upload','download'}: continue
                size=raw.get('size_bytes');digest=raw.get('sha256','')
                if type(size) is not int or not 0<=size<=MAX_TRANSFER_BYTES or not re.fullmatch('[0-9a-f]{64}',digest): continue
                path=self.root/(tid+'.data')
                if not path.is_file() or path.is_symlink() or path.stat().st_size!=size: continue
                self._capacity(size)
                self._items[tid]={'transfer_id':tid,'file_name':name,'size_bytes':size,'sha256':digest,
                                 'direction':raw['direction'],'complete':True,'received_bytes':size,'path':path,'leases':0}
        except (OSError,ValueError,TypeError,AttributeError):
            # Keep bytes on disk, rather than deleting user downloads when an index is damaged.
            # The UI surfaces this condition instead of silently resetting the disk quota.
            raise ValueError('本地传输索引损坏；请备份 transfers 目录后修复或清理') from None
        # Incomplete staging files have no durable approval and cannot resume after restart.
        for path in self.root.glob('*.data'):
            if re.fullmatch('[0-9a-f]{32}',path.stem) and path.stem not in self._items:
                path.unlink(missing_ok=True)

    def _persist(self):
        self.root.mkdir(parents=True,exist_ok=True)
        tmp=self.root/'index.json.tmp'
        tmp.write_text(json.dumps([self.info(k) for k,v in self._items.items() if v['complete']],ensure_ascii=False),encoding='utf-8')
        os.replace(tmp,self.root/'index.json')

    def _capacity(self, size):
        if type(size) is not int or not 0 <= size <= MAX_TRANSFER_BYTES:
            raise ValueError('单次传输上限 64 MiB')
        if sum(v['size_bytes'] for v in self._items.values()) + size > MAX_CACHE_BYTES:
            raise ValueError('本次会话的传输缓存超过 256 MiB；请在本地清理已完成的传输')
        if len(self._items) >= 100: raise ValueError('传输缓存项目已达 100 项')

    def begin(self, name, size, sha256, *, direction='upload'):
        safe_name(name)
        if not re.fullmatch('[0-9a-f]{64}', sha256): raise ValueError('需要文件的 SHA256 摘要')
        with self._lock:
            self._capacity(size)
            self.root.mkdir(parents=True, exist_ok=True)
            tid=uuid.uuid4().hex
            path=self.root/(tid+'.data')
            path.touch(mode=0o600, exist_ok=False)
            self._items[tid]={'transfer_id':tid, 'file_name':name, 'size_bytes':size, 'sha256':sha256,
                             'direction':direction, 'complete':False, 'received_bytes':0, 'path':path, 'leases':0}
            self._persist()
            return self.info(tid)

    def reserve_download(self, name):
        return self.begin(name, MAX_TRANSFER_BYTES, '0'*64, direction='download')

    def _get(self, tid):
        if not isinstance(tid,str) or tid not in self._items: raise ValueError('传输 ID 无效或已被清理')
        return self._items[tid]

    def info(self, tid):
        with self._lock: return {k:v for k,v in self._get(tid).items() if k not in {'path', 'leases'}}

    def path(self, tid, *, complete=False):
        with self._lock:
            item=self._get(tid)
            if complete and not item['complete']: raise ValueError('文件尚未完整接收并校验')
            return item['path']

    def append(self, tid, offset, data_base64, final=False):
        if type(offset) is not int or offset < 0 or type(final) is not bool: raise ValueError('分块参数无效')
        if not isinstance(data_base64,str) or len(data_base64) > 45000: raise ValueError('单个分块最多 32 KiB')
        try: data=base64.b64decode(data_base64,validate=True)
        except Exception: raise ValueError('分块必须为有效 Base64') from None
        if len(data) > 32768: raise ValueError('单个分块最多 32 KiB')
        with self._lock:
            item=self._get(tid)
            if item['direction'] != 'upload': raise ValueError('此 ID 不接受上传分块')
            current=item['received_bytes']
            if offset < current or item['complete']:
                with item['path'].open('rb') as source:
                    source.seek(offset)
                    if offset+len(data) > current or source.read(len(data)) != data: raise ValueError('重试分块与已保存内容不一致')
                return self.info(tid)
            if item['complete'] or offset != current or current+len(data) > item['size_bytes']:
                raise ValueError('分块必须顺序提交，且不能超过声明大小')
            with item['path'].open('ab') as out: out.write(data)
            item['received_bytes']+=len(data)
            if final:
                if item['received_bytes'] != item['size_bytes']: raise ValueError('最后一块提交时文件大小尚未匹配')
                if self._hash(item['path']) != item['sha256']:
                    item['path'].unlink(missing_ok=True); del self._items[tid]
                    raise ValueError('SHA256 校验失败；已删除缓存')
                item['complete']=True
                self._persist()
            return self.info(tid)

    @staticmethod
    def _hash(path):
        digest=hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda:source.read(1024*1024),b''): digest.update(chunk)
        return digest.hexdigest()

    def finish_download(self, tid):
        with self._lock:
            item=self._get(tid); size=item['path'].stat().st_size
            if size > MAX_TRANSFER_BYTES: raise ValueError('下载超过 64 MiB 上限')
            item.update(size_bytes=size, received_bytes=size, sha256=self._hash(item['path']), complete=True)
            self._persist()
            return self.info(tid)

    def import_local(self, path: Path):
        size=path.stat().st_size
        item=self.begin(path.name,size,self._hash(path))
        try:
            shutil.copyfile(path,self.path(item['transfer_id']))
            if self._hash(self.path(item['transfer_id'])) != item['sha256']:
                raise ValueError('选择的文件在准备期间发生变化，请重新选择')
            with self._lock:
                self._items[item['transfer_id']].update(complete=True,received_bytes=size)
                self._persist()
            return self.info(item['transfer_id'])
        except BaseException:
            self.remove(item['transfer_id']); raise

    def read(self, tid, offset=0, limit=32768):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 32768:
            raise ValueError('读取偏移或分块大小无效')
        with self._lock:
            item=self._get(tid)
            if item['direction'] != 'download' or not item['complete']: raise ValueError('该下载尚未完成')
            with item['path'].open('rb') as source: source.seek(offset); data=source.read(limit)
            return {**self.info(tid),'offset':offset,'next_offset':offset+len(data), 'eof':offset+len(data)>=item['size_bytes'],
                    'data_base64':base64.b64encode(data).decode('ascii')}

    def lease(self, tid):
        with self._lock:
            item=self._get(tid)
            if not item['complete']: raise ValueError('文件尚未准备完成')
            if self._hash(item['path']) != item['sha256']: raise ValueError('缓存文件被修改，需重新选择或上传')
            item['leases']+=1
            return self.info(tid)

    def release(self, tid):
        with self._lock:
            if tid in self._items: self._items[tid]['leases']=max(0,self._items[tid]['leases']-1)

    def remove(self, tid, *, force=False):
        with self._lock:
            item=self._get(tid)
            if item['leases']: raise ValueError('此文件关联未完成请求，不能清理')
            if item['direction']=='download' and not item['complete'] and not force:
                raise ValueError('下载请求未完成，请先终止或撤回请求')
            item['path'].unlink(missing_ok=True); del self._items[tid]
            self._persist()

    def list(self):
        with self._lock: return [self.info(tid) for tid in self._items]
