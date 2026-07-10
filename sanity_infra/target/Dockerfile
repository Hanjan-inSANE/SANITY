# sanity_infra/target/Dockerfile - MAVLink smoke target for local QGC/SANITY checks.
# This is not ArduPilot or Damn Vulnerable Drone. Replace it with the real
# ArduPilot/DVD adapter when SANITY component 9 is implemented.
FROM python:3.11-slim

WORKDIR /sitl
ENV PYTHONUNBUFFERED=1

COPY mavlink_smoke_target.py /sitl/mavlink_smoke_target.py
EXPOSE 5760/tcp
CMD ["python", "/sitl/mavlink_smoke_target.py"]
