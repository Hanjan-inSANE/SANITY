# sanity_scenario_manager/submitter.py
import uuid, os
from sanity_common.contracts import SubmissionBundle, PoV, Patch

class Submitter:
    def __init__(self, tree_id, cfg, bus, state):
        self.tree_id=tree_id; self.cfg=cfg; self.bus=bus; self.state=state
        self._by_pov: dict[str, dict] = {}          # pov_id → {"patch_ref"?} : PoV와 Patch를 한 번들로 병합

    def collect(self, artifact: dict) -> None:                     # 2.4.1 (동기)
        """공격 성공 시 {kind:pov, pov_id}, 방어 성공 시 {kind:patch, ref, scope_id} 두 번 호출됨.
        pov_id로 병합해 한 SubmissionBundle에 PoV+Patch를 함께 담는다(DM-9)."""
        if artifact.get("kind") == "pov":
            self._by_pov.setdefault(artifact["pov_id"], {})
        elif artifact.get("kind") == "patch":
            pj = self.state.r.get(artifact["ref"])                 # st:patch:{id}
            if pj:
                patch = Patch.model_validate_json(pj)
                self._by_pov.setdefault(patch.pov_id, {})["patch_ref"] = artifact["ref"]

    def finalize(self) -> None:                                    # 2.4.2 + 2.4.3 (동기)
        for pov_id, rec in self._by_pov.items():
            bundle = self._package(pov_id, rec)                    # 채점정책 어댑터로 scoring_meta 채움
            self.bus.publish("sanity:submit", bundle.model_dump()) # 0(DAH sink)
            if self.cfg.scoring_adapter == "local":                # FR-SM-11 예선 로컬 sink
                os.makedirs("/submissions", exist_ok=True)
                with open(f"/submissions/{bundle.bundle_id}.json","w") as f:
                    f.write(bundle.model_dump_json(indent=2))

    def _package(self, pov_id: str, rec: dict) -> SubmissionBundle:  # FR-SM-12 어댑터 경계
        pj = self.state.r.get(f"st:pov:{pov_id}")
        pov = PoV.model_validate_json(pj) if pj else None
        patch = None
        if rec.get("patch_ref"):
            pt = self.state.r.get(rec["patch_ref"])
            patch = Patch.model_validate_json(pt) if pt else None
        meta = self._scoring_adapter(rec)                          # 본선: DAH 채점 규칙 바인딩(보류)
        return SubmissionBundle(bundle_id="b_"+uuid.uuid4().hex[:12], pov=pov, patch=patch,
                                evidence_bundle_ref=rec.get("evidence_ref"), scoring_meta=meta)

    def _scoring_adapter(self, art: dict) -> dict:                 # SR-CONFIG-01
        if self.cfg.scoring_adapter == "local": return {"mode":"local"}
        raise NotImplementedError("본선 DAH 채점 어댑터는 예선 범위 밖(FR-SM-12)")
