"""무인(백그라운드) 실행 지원: 절전 방지와 로그 파일 출력.

화면이 잠겨도 프로세스는 계속 돌지만, PC가 절전(대기) 모드로 들어가면 점검과 알림이 멈춘다.
Windows 에서는 SetThreadExecutionState 로 '시스템 절전만 막고 화면은 꺼지게' 요청한다.
(`powercfg /requests` 의 SYSTEM 항목에서 확인할 수 있다.)
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


def keep_awake() -> bool:
    """시스템 절전 방지 요청(화면 꺼짐·잠금은 허용). 지원하지 않는 OS 면 False.

    요청은 호출한 스레드가 살아 있는 동안 유지되므로 watch 를 실행하는 메인 스레드에서 호출한다.
    """
    if sys.platform != "win32":
        return False
    import ctypes

    return bool(ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED))


def allow_sleep() -> None:
    if sys.platform == "win32":
        import ctypes

        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)


class RotatingLog:
    """print() 대상으로 쓸 수 있는 파일 객체. max_bytes 를 넘으면 .1, .2 … 로 밀어낸다.

    pythonw.exe(콘솔 없는 실행)에서는 sys.stdout/stderr 가 None 이라 출력이 사라지므로,
    작업 스케줄러로 실행할 때 이 로그로 바꿔 둔다.
    """

    def __init__(self, path: str | Path, max_bytes: int = 5 * 1024 * 1024, backups: int = 3):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.backups = backups
        self.lock = threading.Lock()
        self.fh = self.path.open("a", encoding="utf-8")

    def write(self, text: str) -> int:
        with self.lock:
            self.fh.write(text)
            self.fh.flush()
            if self.fh.tell() >= self.max_bytes:
                self._rotate()
        return len(text)

    def flush(self) -> None:
        with self.lock:
            self.fh.flush()

    def _rotate(self) -> None:
        self.fh.close()
        for i in range(self.backups - 1, 0, -1):
            src = Path(f"{self.path}.{i}")
            if src.exists():
                os.replace(src, f"{self.path}.{i + 1}")
        os.replace(self.path, f"{self.path}.1")
        self.fh = self.path.open("a", encoding="utf-8")

    def isatty(self) -> bool:
        return False

    def close(self) -> None:
        with self.lock:
            self.fh.close()
