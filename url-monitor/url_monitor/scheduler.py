"""점검 실행: 1회 전체 점검(check_all)과 주기 점검(watch)."""

from __future__ import annotations

import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from typing import Callable

from .evaluator import check_target, now_iso
from .models import CheckResult, Target
from .notifier import decide, dispatch, events_without_history
from .store import Store


def _log_error(log, what: str, exc: Exception) -> None:
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [오류] {what}: {type(exc).__name__}: {exc}", file=log or sys.stderr, flush=True)


def check_all(targets: list[Target], workers: int = 20, on_result: Callable[[CheckResult], None] | None = None) -> list[CheckResult]:
    """모든 대상을 병렬로 점검해 등록 순서대로 돌려준다."""
    targets = [t for t in targets if t.enabled]
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        futures = [pool.submit(check_target, t) for t in targets]
        results = []
        for f in futures:
            res = f.result()
            if on_result:
                on_result(res)
            results.append(res)
    return results


def process_results(results: list[CheckResult], store: Store | None, notify_cfg: dict | None, log=None) -> list:
    """이력 저장 + 상태 전이 알림. 보낸 이벤트 목록을 돌려준다."""
    if store is None:
        events = events_without_history(results, notify_cfg or {}) if notify_cfg else []
        if events:
            dispatch(events, notify_cfg, log)
        return events
    events = []
    for res in results:
        prev = store.record(res)
        if notify_cfg:
            ev = decide(prev, res, notify_cfg)
            if ev:
                events.append(ev)
    if events and dispatch(events, notify_cfg, log):
        sent_at = now_iso()
        for ev in events:
            store.mark_notified(ev.result.target.key, sent_at)
    return events


def watch(targets: list[Target], store: Store, notify_cfg: dict | None, workers: int = 20,
          on_cycle: Callable[[list[CheckResult], dict[str, CheckResult]], None] | None = None,
          max_rounds: int = 0, retention_days: int = 90, log=None) -> None:
    """대상마다 interval_sec 간격으로 점검한다. Ctrl+C 로 종료.

    on_cycle(이번에 끝난 결과들, 대상별 최신 결과) 는 결과가 나올 때마다 호출된다(상태 페이지 갱신용).
    max_rounds > 0 이면 모든 대상을 그 횟수만큼 점검한 뒤 끝낸다(테스트·1회성 실행용).
    처리 중 예외가 나도 기록만 하고 계속 돈다(화면 잠금·무인 실행 중 조용히 멈추지 않도록).
    """
    targets = [t for t in targets if t.enabled]
    next_due = {t.key: 0.0 for t in targets}
    rounds = {t.key: 0 for t in targets}
    latest: dict[str, CheckResult] = {}
    inflight: dict[str, Future] = {}
    last_purge: float | None = None
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        try:
            while True:
                now = time.monotonic()
                for t in targets:
                    if t.key in inflight or now < next_due[t.key]:
                        continue
                    if max_rounds and rounds[t.key] >= max_rounds:
                        continue
                    inflight[t.key] = pool.submit(check_target, t)
                    next_due[t.key] = now + t.interval_sec
                done = [k for k, f in inflight.items() if f.done()]
                if done:
                    results = []
                    for k in done:
                        try:
                            results.append(inflight.pop(k).result())
                        except Exception as exc:  # 점검 코드 자체의 예기치 못한 오류
                            rounds[k] += 1
                            _log_error(log, f"{k} 점검 중 오류", exc)
                    for r in results:
                        latest[r.target.key] = r
                        rounds[r.target.key] += 1
                    try:
                        process_results(results, store, notify_cfg, log)
                        if on_cycle:
                            on_cycle(results, latest)
                    except Exception as exc:
                        _log_error(log, "결과 처리 중 오류", exc)
                if last_purge is None or now - last_purge > 86400:
                    try:
                        store.purge(retention_days)
                    except Exception as exc:
                        _log_error(log, "이력 정리 중 오류", exc)
                    last_purge = now
                if max_rounds and not inflight and all(n >= max_rounds for n in rounds.values()):
                    return
                time.sleep(0.2)
        except KeyboardInterrupt:
            print(f"\n[{datetime.now():%H:%M:%S}] 모니터링을 종료합니다.", file=log or sys.stderr)
            for f in inflight.values():
                f.cancel()
