param(
    [string]$SanityRoot = "C:\Users\trust\SANITY",
    [string]$DvdRoot = "C:\Users\trust\Damn-Vulnerable-Drone",
    [string]$TreeId = "t_48d1adebd2f0215c",
    [switch]$SkipQgcCheck,
    [switch]$SkipAttack
)

$ErrorActionPreference = "Stop"

function Invoke-Docker {
    param(
        [string[]]$DockerArgs,
        [string]$WorkDir = $SanityRoot,
        [switch]$AllowFailure
    )
    Push-Location $WorkDir
    try {
        Write-Host ">> docker $($DockerArgs -join ' ')" -ForegroundColor Cyan
        & docker @DockerArgs
        $code = $LASTEXITCODE
        if ($code -ne 0 -and -not $AllowFailure) {
            throw "docker command failed with exit code ${code}: docker $($DockerArgs -join ' ')"
        }
        return $code
    }
    finally {
        Pop-Location
    }
}

function Invoke-Bash {
    param(
        [string]$Container,
        [string]$Command,
        [switch]$Detached,
        [switch]$AllowFailure
    )
    $dockerArgs = @("exec")
    if ($Detached) { $dockerArgs += "-d" }
    $dockerArgs += @($Container, "bash", "-lc", $Command)
    Invoke-Docker -DockerArgs $dockerArgs -AllowFailure:$AllowFailure | Out-Null
}

function Wait-Docker {
    Write-Host "Waiting for Docker Desktop..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 90; $i++) {
        & docker info *> $null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 2
    }
    throw "Docker is not ready. Start Docker Desktop first."
}

function Wait-Container {
    param([string]$Name)
    for ($i = 0; $i -lt 60; $i++) {
        $running = (& docker inspect -f "{{.State.Running}}" $Name 2>$null)
        if (($running | Select-Object -First 1) -eq "true") { return }
        Start-Sleep -Seconds 1
    }
    throw "Container is not running: $Name"
}

function Wait-Gateway {
    Write-Host "Waiting for SANITY gateway..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 60; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:4000/health/liveliness" -TimeoutSec 2 | Out-Null
            return
        }
        catch {
            Start-Sleep -Seconds 2
        }
    }
    throw "SANITY gateway did not become healthy on http://127.0.0.1:4000."
}

function Wait-CompanionSerial {
    Write-Host "Waiting for DVD virtual serial link..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 60; $i++) {
        & docker exec companion-computer-lite bash -lc "test -e /dev/ttyUSB0" *> $null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 1
    }
    throw "companion-computer-lite cannot see /dev/ttyUSB0. Check /tmp/sitl.log in flight-controller-lite."
}

function Wait-MavlinkRouter {
    Write-Host "Waiting for MAVLink router..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 20; $i++) {
        & docker exec companion-computer-lite bash -lc "pgrep -af mavlink-routerd" *> $null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 1
    }
    Write-Host "--- /tmp/mavlink-routerd.err ---" -ForegroundColor Red
    & docker exec companion-computer-lite bash -lc "cat /tmp/mavlink-routerd.err 2>&1 || true"
    throw "mavlink-routerd is not running."
}

function Get-HostGatewayIp {
    $lines = & docker exec companion-computer-lite getent hosts host.docker.internal 2>$null
    foreach ($line in $lines) {
        $candidate = (($line -split "\s+") | Where-Object { $_ } | Select-Object -First 1)
        if ($candidate -match "^\d{1,3}(\.\d{1,3}){3}$") {
            return $candidate
        }
    }
    return "192.168.65.254"
}

function Wait-QgcUdp14550 {
    Write-Host "Waiting for QGC UDP 14550 listener..." -ForegroundColor Yellow
    for ($i = 0; $i -lt 60; $i++) {
        $qgc = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "QGroundControl" }
        $udp = Get-NetUDPEndpoint -LocalPort 14550 -ErrorAction SilentlyContinue
        if ($qgc -and $udp) {
            $rows = $udp | Select-Object LocalAddress, LocalPort, OwningProcess
            Write-Host "QGC/UDP check passed:" -ForegroundColor Green
            $rows | Format-Table -AutoSize | Out-Host
            return
        }
        Start-Sleep -Seconds 2
    }
    Write-Host "QGroundControl is running, but Windows does not show a UDP 14550 listener." -ForegroundColor Red
    Write-Host "In QGC: Application Settings -> Comm Links -> Add/Edit -> Type UDP -> Listening Port 14550 -> Connect." -ForegroundColor Yellow
    throw "QGC UDP 14550 is not listening. Re-enable the QGC UDP link, then run the script again."
}

function Ensure-AttackTreeViewer {
    $name = "sanity-attack-tree-viewer"
    $running = (& docker inspect -f "{{.State.Running}}" $name 2>$null | Select-Object -First 1)
    if ($running -eq "true") {
        Write-Host "SANITY attack-tree viewer already running at http://localhost:8090" -ForegroundColor Green
        return
    }

    $existing = (& docker ps -a --filter "name=^/${name}$" --format "{{.Names}}" | Select-Object -First 1)
    if ($existing -eq $name) {
        Invoke-Docker -DockerArgs @("start", $name) | Out-Null
        Write-Host "SANITY attack-tree viewer started at http://localhost:8090" -ForegroundColor Green
        return
    }

    Invoke-Docker -WorkDir $SanityRoot -DockerArgs @(
        "run", "-d",
        "--name", $name,
        "--network", "control",
        "-p", "8090:8090",
        "-v", "sanity-logs:/logs:ro",
        "-v", "submissions:/submissions:ro",
        "-v", "${SanityRoot}\tools:/app/tools:ro",
        "-e", "SANITY_LOG_DIR=/logs",
        "-e", "SANITY_SUB_DIR=/submissions",
        "-e", "REDIS_URL_STATE=redis://redis:6379/1",
        "-e", "SANITY_VIEWER_PORT=8090",
        "sanity-scenario-manager:latest",
        "python3", "/app/tools/viewer.py"
    ) | Out-Null
    Write-Host "SANITY attack-tree viewer started at http://localhost:8090" -ForegroundColor Green
}

Wait-Docker

Write-Host "`n[1/7] Starting SANITY Redis/Gateway" -ForegroundColor Green
Invoke-Docker -WorkDir (Join-Path $SanityRoot "deploy") -DockerArgs @(
    "compose", "-f", "docker-compose.yml", "-f", "docker-compose.demo.yml",
    "--env-file", ".env", "up", "-d", "redis", "gateway-db", "gateway"
) | Out-Null
Wait-Container "sanity-redis-1"
Wait-Gateway
Write-Host "Stopping SANITY demo targets to free host UDP 14550/14551 for QGC..." -ForegroundColor Yellow
Invoke-Docker -WorkDir (Join-Path $SanityRoot "deploy") -DockerArgs @(
    "compose", "-f", "docker-compose.yml", "-f", "docker-compose.demo.yml",
    "--env-file", ".env", "stop", "target-sitl-a", "target-sitl-b"
) -AllowFailure | Out-Null

Write-Host "`n[2/7] Ensuring DVD attack driver image is current" -ForegroundColor Green
Invoke-Docker -WorkDir $SanityRoot -DockerArgs @(
    "build", "-t", "sanity_dvd_attack:latest", "-f", "tools/Dockerfile.dvd_attack", "."
) | Out-Null
Ensure-AttackTreeViewer

Write-Host "`n[3/7] Starting DVD Lite containers" -ForegroundColor Green
Invoke-Docker -WorkDir $DvdRoot -DockerArgs @("compose", "-f", "docker-compose-lite.yaml", "up", "-d") | Out-Null
Wait-Container "flight-controller-lite"
Wait-Container "companion-computer-lite"
Wait-Container "ground-control-station-lite"
Wait-Container "simulator-lite"

Write-Host "`n[4/7] Starting ArduPilot SITL inside DVD flight controller" -ForegroundColor Green
Invoke-Bash -Container "flight-controller-lite" -Command "pkill -f sim_vehicle.py || true; pkill -f '/ardupilot/build/sitl/bin/arducopter' || true" -AllowFailure
Invoke-Bash -Container "flight-controller-lite" -Detached -Command "cd /ardupilot && Tools/autotest/sim_vehicle.py -v ArduCopter --add-param-file drone.parm --custom-location 37.241861,-115.796917,137,340 -f quad --no-rebuild --no-mavproxy -A '--serial0=uart:/dev/ttyACM0:57600' > /tmp/sitl.log 2>&1"
Start-Sleep -Seconds 8
Wait-CompanionSerial

Write-Host "`n[5/7] Starting MAVLink router inside DVD companion computer" -ForegroundColor Green
$hostGatewayIp = Get-HostGatewayIp
Invoke-Bash -Container "companion-computer-lite" -Command "pkill -f mavlink-routerd || true" -AllowFailure
$routerCommand = "mkdir -p /var/log/mavlink-router; mavlink-routerd -r -l /var/log/mavlink-router --tcp-port 5760 /dev/ttyUSB0:57600 -e 127.0.0.1:14540 -e 10.13.0.4:14550 -e ${hostGatewayIp}:14550 >/tmp/mavlink-routerd.out 2>/tmp/mavlink-routerd.err"
Invoke-Bash -Container "companion-computer-lite" -Detached -Command $routerCommand
Wait-MavlinkRouter

if (-not $SkipQgcCheck) {
    Wait-QgcUdp14550
}

Write-Host "`n[6/7] Running DVD takeoff and autopilot stages" -ForegroundColor Green
Invoke-Docker -WorkDir $DvdRoot -DockerArgs @("exec", "ground-control-station-lite", "timeout", "90", "python3", "/opt/gcs/stages/arm-and-takeoff.py") | Out-Null
Invoke-Docker -WorkDir $DvdRoot -DockerArgs @("exec", "ground-control-station-lite", "timeout", "120", "python3", "/opt/gcs/stages/autopilot-flight.py") | Out-Null

$exists = (& docker exec sanity-redis-1 redis-cli -n 1 EXISTS "st:tree:$TreeId" | Select-Object -First 1)
if ($exists -ne "1") {
    Write-Host "Available attack trees:" -ForegroundColor Yellow
    & docker exec sanity-redis-1 redis-cli -n 1 keys "st:tree:*"
    throw "Attack tree st:tree:$TreeId is missing. Regenerate SANITY threat trees or use an existing key with -TreeId."
}

Write-Host "`nQGC must listen on UDP 14550. Do not use 127.0.0.1 TCP 5760 for DVD Lite." -ForegroundColor Yellow
Write-Host "DVD MAVLink router also sends telemetry to host gateway ${hostGatewayIp}:14550." -ForegroundColor Yellow

if ($SkipAttack) {
    Write-Host "`nSkipped attack. Drone is staged; run this script again without -SkipAttack to execute the attack." -ForegroundColor Green
    exit 0
}

Write-Host "`n[7/7] Executing SANITY DVD attack driver against tree $TreeId" -ForegroundColor Green
Invoke-Docker -WorkDir $SanityRoot -DockerArgs @(
    "run", "--rm", "--network", "simulator",
    "-v", "sanity-logs:/logs",
    "--env-file", "deploy\.env",
    "-e", "LITELLM_API_BASE=http://host.docker.internal:4000",
    "-e", "REDIS_URL_STATE=redis://host.docker.internal:6379/1",
    "-e", "SANITY_LOG_DIR=/logs",
    "-e", "SANITY_MAV_ENDPOINT=tcp:10.13.0.3:5760",
    "-e", "SANITY_GATEWAY_MODEL=sane-sonnet",
    "-e", "SANITY_TREE_ID=$TreeId",
    "sanity_dvd_attack:latest"
) | Out-Null

Write-Host "`nDone. Latest DVD attack logs are in Docker volume sanity-logs." -ForegroundColor Green
