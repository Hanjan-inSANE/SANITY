# sanity_common/aio.py
import asyncio, threading
_LOOP = asyncio.new_event_loop()
threading.Thread(target=_LOOP.run_forever, daemon=True).start()   # 백그라운드 전용 루프(1개)
def run_sync(coro):
    """async 코루틴(예: Toolset MCP 호출)을 동기 코드에서 안전하게 실행한다.
    전 컴포넌트가 `from sanity_common.aio import run_sync as _await` 로 쓴다."""
    return asyncio.run_coroutine_threadsafe(coro, _LOOP).result()
