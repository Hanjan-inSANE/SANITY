# sanity_infra/target/Dockerfile — 9. Target: DVD(Damn Vulnerable Drone) ArduPilot SITL (PLACEHOLDER)
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ 컴포넌트 9(별도 세션 담당, §00-1/§00-10)가 실제 DVD SITL 빌드로 채운다.
#   여기서는 deploy/docker-compose.yml 의 target-sitl-a/b 가 유효한 build context 를 갖도록
#   최소 골격만 둔다. target 은 격리 네트워크(internal)에 두어 인터넷·제어평면과 분리된다(SR-SEC-02).
#
# TODO(9): ArduPilot SITL + Damn Vulnerable Drone 설치. 개략:
#   - git clone --recursive https://github.com/ArduPilot/ardupilot
#   - ./waf configure --board sitl && ./waf copter
#   - MAVLink 엔드포인트 :5760 노출(로직 도구 run_tool 의 {mav_endpoint} 대상)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /sitl
ENV PYTHONUNBUFFERED=1

# 실제 SITL 로 교체되기 전까지 컨테이너가 살아있도록만 유지(compose 스택 기동 검증용).
CMD ["sleep", "infinity"]
