# sanity_common/contracts.py
from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel

# ---- DM-1 SystemModel (threat_modeler 산출 반영; SM은 보통 DM-2만 받으므로 참고용) ----
class DmNode(BaseModel):
    guid: str; type: Literal["process","external","store","element"]; label: str
    x: float = 0.0; y: float = 0.0; w: float = 150.0; h: float = 60.0
class DmEdge(BaseModel):
    guid: str; label: str; source: str; target: str
class SystemModel(BaseModel):
    nodes: list[DmNode] = []; edges: list[DmEdge] = []

# ---- DM-2 AttackTree (threat_modeler 원출력: 루트 노드가 곧 트리, 재귀 중첩) ----
# 주의: TM 원출력에는 tnode_id/tree_id/gate/atom 없음. 아래 두 필드(tnode_id, tree_id)는
# SM(2.1) 수신 시점에 §4 알고리즘으로 부여되어 "주입"된 뒤 사용된다(REQ DM-2 v4, INV-4).
class Evidence(BaseModel):
    id: str; note: str = ""
class TreeNode(BaseModel):
    summary: str
    attack_context: str = ""
    evidence: list[Evidence] = []
    logic: Optional[Literal["AND","OR"]] = None      # leaf는 생략(None)
    children: Optional[list["TreeNode"]] = None       # leaf는 생략(None)
    dfd_component: Optional[str] = None
    dfd_channel: Optional[str] = None
    out_of_band: Optional[bool] = None
    precondition: Optional[bool] = None
    notes: Optional[str] = None
    # --- SM이 §4에서 주입하는 식별자(원 TM 출력엔 없음) ---
    tnode_id: Optional[str] = None                    # tree_id 범위 내 유일
    def is_leaf(self) -> bool:
        return not (self.children or [])
TreeNode.model_rebuild()

# ---- DM-3 AttackPath (2.1 산출) ----
class AttackPath(BaseModel):
    path_id: str
    tree_id: str
    node_seq: list[str]                               # 각 원소=tnode_id, leaf→root 순
    gate_seq: list[Literal["AND","OR","LEAF"]]        # node_seq와 index 정렬

# ---- DM-4 CompromiseContext (2.3 producer, 3.1.1 consumer) ----
class Foothold(BaseModel):
    tnode_id: str
    access: str                                       # 예: rce|auth-bypass|mavlink-session
    privilege: str                                    # 예: user|root|operator
    artifacts: dict = {}                              # 세션/토큰/파일 참조
class CompromiseContext(BaseModel):
    path_id: str
    compromised: list[Foothold] = []                  # node_seq prefix 순서

# ---- DM-5 InstanceState (State Store) ----
class InstanceState(BaseModel):
    scope_id: str
    kind: Literal["scenario","attacker","defender"]
    state: Literal["PENDING","RUNNING","SUCCESS","FAIL"]
    retries: int = 0

# ---- DM-6 AttackContext (Attacker → 2.3 → Defender) ----
class PoV(BaseModel):
    pov_id: str
    tnode_id: str
    tool: str
    input_blob_ref: str                               # replay용 성공 입력(Toolset artifact ref)
    pre_snapshot_ref: str                             # (실제 Toolset엔 snapshot 없음: crash=빈 값, replay로 대체 §8.4)
    exploit_signature: str
    effect: Literal["crash","dos","unauthorized","spoof"]
    replay_command: Optional[str] = None              # Toolset PoV
    crash_report_ref: Optional[str] = None            # Toolset PoV
    # ⚠ DM-6에 없는 필드는 추가하지 않는다. "공격 클래스(crash/logic)"는 저장 필드가 아니라
    # PoV.tool의 kind에서 결정론적으로 파생한다(FR-AT-05, DM-6 비고). 파생: attack_class_of() (§3.1).
class AttackContext(BaseModel):
    pov: PoV
    compromise_ctx: CompromiseContext
    target_ref: str                                   # = Attacker workspace_root(crash) 또는 SITL 엔드포인트(logic); §00-10

# ---- DM-7 Patch (4 산출) ----
class Patch(BaseModel):
    patch_id: str
    pov_id: str
    target_files: list[str] = []
    diff: str                                         # unified diff (crash) 또는 config/규칙 diff(logic)
    applies_to: str                                   # clone 핸들

# ---- DM-8 EventEnvelope / StatusEvent (전 컴포넌트 → Log; 에이전트 → 2.3) ----
class EventEnvelope(BaseModel):
    ts: float
    trace_id: str
    component: str                                    # "0".."9" 또는 서브넘버 "2.3"
    scope_id: Optional[str] = None
    event_type: Literal["llm_call","status","tool_call","artifact","error"]
    state: Optional[Literal["PENDING","RUNNING","SUCCESS","FAIL"]] = None  # status 계열
    payload_ref: Optional[str] = None                 # status=SUCCESS면 AttackContext(DM-6) ref
    # event_type=llm_call 확장(6.4 기록)
    provider: Optional[str] = None; model: Optional[str] = None
    prompt_tokens: Optional[int] = None; completion_tokens: Optional[int] = None
    cost: Optional[float] = None; latency_ms: Optional[int] = None
    request_ref: Optional[str] = None; response_ref: Optional[str] = None  # 마스킹된 ref
    stop_reason: Optional[str] = None

# 비고(6/7 통합): 위 EventEnvelope는 **상태 버스(sanity:status, 에이전트→2.3)의 pydantic 정본**이다.
# Log(7)로 남길 때는 gateway_log의 `sanity_log.Event`/`LLMCallRecord`로 기록된다(동일 DM-8 필드집합).
# 매핑: EventEnvelope ↔ sanity_log.Event 는 component/event_type/trace_id/scope_id/state/payload_ref/ts 로 1:1.
# llm_call 확장의 `cost`(DM-8)는 sanity_log.LLMCallRecord에서 `cost_usd`로 기록된다(LiteLLM 원가 그대로; 동일 값).
# 상태 이벤트를 로그로도 남기려면 `LogWriter.emit(envelope.model_dump())`를 쓴다(§9).

# ---- DM-9 SubmissionBundle (2.4 → 0) ----
class SubmissionBundle(BaseModel):
    bundle_id: str
    pov: Optional[PoV] = None
    patch: Optional[Patch] = None
    evidence_bundle_ref: Optional[str] = None         # Toolset DefenseEvidenceBundle 참조
    scoring_meta: dict = {}                            # 채점정책 어댑터가 채움

# ---- DM-10 ToolDescriptor (Toolset 8 레지스트리 정본) ----
KIND_ENUM = ("builder","test_runner","fuzzer","debugger","tracer","sanitizer","coverage",
             "static_analyzer","patcher","config_hardener","ids_rule_validator","reporter",
             "network_scanner","network_attacker")     # 14종 (REQ DM-10, ARCH §8)
class ToolExecution(BaseModel):
    mode: Literal["host","container","internal"]
    image: Optional[str] = None
    entrypoint: list[str] = []
    command_template: list[str] = []                  # {placeholder} 치환
class ToolDescriptor(BaseModel):
    tool_id: str
    display_name: str
    kind: str                                         # KIND_ENUM 중 하나
    execution: ToolExecution
    security_profile: dict = {}
    evidence_policy: dict = {}
    params_schema_ref: str = ""
    priority: Literal["P0","P1","P2","P3"] = "P2"

# ---- DM-11 BudgetGrant (2.2 Allocator → 6.2) ----
class BudgetGrant(BaseModel):
    scope_id: str                                     # DM-5와 정합
    virtual_key: str                                  # LiteLLM 가상키
    token_budget: int
    rpm_limit: int
    tpm_limit: int
    wall_clock_s: Optional[int] = None                # Allocator가 강제(Gateway 아님)
    expires_at: Optional[float] = None


def assert_inv3_unique(state, tree_id, tnode_id, exploit_signature) -> bool:
    """INV-3: dedup 키 (tree_id,tnode_id,exploit_signature)는 State Store에서 유일.
    True=신규(진행), False=중복(디스패치 생략). 구현은 §6 dedup_check."""
    return state.dedup_check_and_add(tree_id, tnode_id, exploit_signature)


# ---- §3.1 공격 클래스 파생 (MUST, FR-AT-05/INV-2 — DM-6 필드 추가 없이) ----
LOGIC_KINDS = {"network_scanner","network_attacker","config_hardener","ids_rule_validator"}
def attack_class_of_kind(kind: str) -> str:
    """logic 계열 kind면 'logic', 그 외(crash 파이프라인)면 'crash'."""
    return "logic" if kind in LOGIC_KINDS else "crash"
def attack_class_of_tools(kinds: list[str]) -> str:
    """선택 도구 kind 목록 중 하나라도 crash 파이프라인이면 crash 우선(oracle 강한 쪽)."""
    return "crash" if any(k not in LOGIC_KINDS for k in kinds) else "logic"
