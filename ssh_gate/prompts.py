from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field


class PromptCancelled(Exception):
    pass


@dataclass
class LocalPrompt:
    kind: str
    data: dict
    done: threading.Event = field(default_factory=threading.Event)
    answer: object = None


class LocalPrompts:
    """Secrets and host-key approvals exist only in local GUI interactions."""
    def __init__(self):
        self._queue = queue.Queue()
        self._lock = threading.Lock()
        self._pending: list[LocalPrompt] = []
        self._closed = False

    def ask(self, kind: str, data: dict, stop: threading.Event, timeout: float = 120):
        prompt = LocalPrompt(kind, data)
        with self._lock:
            if self._closed:
                raise PromptCancelled("本地窗口已关闭")
            self._pending.append(prompt)
            self._queue.put(prompt)
        deadline = time.monotonic() + timeout
        try:
            while not prompt.done.wait(0.1):
                if stop.is_set() or time.monotonic() >= deadline:
                    raise PromptCancelled("已取消或本地输入超时")
            if prompt.answer is None:
                raise PromptCancelled("用户取消了本地输入")
            return prompt.answer
        finally:
            prompt.done.set()
            with self._lock:
                if prompt in self._pending:
                    self._pending.remove(prompt)

    def next(self):
        while True:
            try:
                prompt = self._queue.get_nowait()
            except queue.Empty:
                return None
            if not prompt.done.is_set():
                return prompt

    def close(self):
        with self._lock:
            self._closed = True
            for prompt in self._pending:
                prompt.answer = None
                prompt.done.set()
