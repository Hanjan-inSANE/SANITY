#!/usr/bin/env python3
import sys, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

def patch(path, old, new, done_marker, label):
    try:
        s = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"  [건너뜀-파일없음] {label}"); return
    if done_marker in s:
        print(f"  [이미적용] {label}"); return
    if old not in s:
        print(f"  [!! 원본못찾음] {label}: {path}"); return
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))
    print(f"  [적용] {label}")

print("=== 런타임 버그 일괄 패치 ===")

patch("sanity_scenario_manager/main.py",
      '    bus.reclaim("sanity:tree:inbox", "g:scenario-manager", "sm-main")',
      '    bus.ensure_group("sanity:tree:inbox", "g:scenario-manager")\n    bus.reclaim("sanity:tree:inbox", "g:scenario-manager", "sm-main")',
      'bus.ensure_group("sanity:tree:inbox", "g:scenario-manager")',
      "1) SM ensure_group before reclaim")

patch("sanity_scenario_manager/allocator.py",
      '        import docker\n        docker.from_env().containers.run(',
      '        import docker\n        _cli = docker.from_env()\n        _c = _cli.containers.run(',
      '_c = _cli.containers.run(',
      "2a) allocator capture container")
patch("sanity_scenario_manager/allocator.py",
      '''            name=f"{role}-{scope_id.replace(':','_')}", remove=True)''',
      '''            name=f"{role}-{scope_id.replace(':','_')}", remove=True)\n        try:\n            _cli.networks.get("target").connect(_c)\n        except Exception:\n            pass''',
      '_cli.networks.get("target").connect(_c)',
      "2b) allocator connect target network")

patch("sanity_defender/agent.py",
      '    workspace_root: str; mav_endpoint: str        # Attacker와 동일 workspace(crash) + 방어검증 SITL(logic)',
      '    workspace_root: str; mav_endpoint: str        # Attacker와 동일 workspace(crash) + 방어검증 SITL(logic)\n    gateway_url: str; _pov: dict; _target_files: list   # 런타임 내부 채널(필수 선언)',
      '_pov: dict; _target_files: list',
      "3) defender DefenderState channels")

patch("sanity_defender/main.py",
      '            workspace_root=p["workspace_root"], mav_endpoint=p["mav_endpoint"],  # Attacker와 동일 workspace',
      '            workspace_root=p["workspace_root"], mav_endpoint=p["mav_endpoint"], gateway_url=p["gateway_url"],  # Attacker와 동일 workspace',
      'gateway_url=p["gateway_url"], ',
      "4) defender init gateway_url")

patch("sanity_defender/verifier.py",
      '        cmp = _await(ts.diag("compare_baseline", {"workspace_root": ws,',
      '        _okc, cmp = _await(ts.sig("compare_baseline", {"workspace_root": ws,',
      '_okc, cmp = _await(ts.sig("compare_baseline"',
      "5) defender compare_baseline diag->sig")

patch("sanity_attacker/executor.py",
      '            find = _await(ts.diag("collect_findings", {"workspace_root": ws, "fuzz_output_dir": fuzz_out, "trace_id": tid}))',
      '            _okf, find = _await(ts.sig("collect_findings", {"workspace_root": ws, "fuzz_output_dir": fuzz_out, "trace_id": tid}))',
      '_okf, find = _await(ts.sig("collect_findings"',
      "6) attacker collect_findings diag->sig")

if os.path.exists("sanity_up.sh"):
    s = open("sanity_up.sh", encoding="utf-8").read()
    if "docker-compose down -v" not in s and "docker-compose down )" in s:
        open("sanity_up.sh","w",encoding="utf-8").write(s.replace("docker-compose down )","docker-compose down -v )"))
        print("  [적용] sanity_up.sh down -> down -v")
    else:
        print("  [이미적용/불필요] sanity_up.sh down -v")

print("=== 완료 ===")
