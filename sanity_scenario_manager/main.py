# sanity_scenario_manager/main.py
import threading
from sanity_common.bus import Bus
from sanity_common.state import State
from sanity_common.config import load_config
from sanity_common.ids import assign_tnode_ids, tree_id_of
from .manager import ScenarioManager

def run() -> None:                                            # 동기(§00-2.1)
    cfg = load_config(); bus = Bus(cfg.redis_url_bus); state = State(cfg.redis_url_state)
    bus.reclaim("sanity:tree:inbox", "g:scenario-manager", "sm-main")   # 재기동 회수(FR-SR-DEPLOY-02)
    running: dict[str, threading.Thread] = {}
    for msg_id, obj in bus.consume("sanity:tree:inbox", "g:scenario-manager", "sm-main"):
        tree = obj["tree"] if "tree" in obj else obj          # DM-2 (threat_modeler 원출력 JSON)
        tid = obj.get("tree_id") or tree_id_of(tree)          # §00-4
        if tid in running and running[tid].is_alive():
            bus.ack("sanity:tree:inbox","g:scenario-manager",msg_id); continue   # 트리당 1 인스턴스
        assign_tnode_ids(tree, dag_mode=cfg.dag_mode)         # §00-4 INV-4
        state.put_tree(tid, tree)                             # 영속(INV-4, FR-SR-DEPLOY-02)
        mgr = ScenarioManager(tid, tree, cfg, bus, state)     # 각 스레드는 자기 Bus 연결을 쓰는 게 안전
        th = threading.Thread(target=mgr.run, name=f"sm-{tid}", daemon=True)
        running[tid] = th; th.start()                         # 트리당 1 스레드(동시성)
        bus.ack("sanity:tree:inbox","g:scenario-manager",msg_id)

if __name__ == "__main__":
    run()
