# start-wazuh.ps1
# Run as Administrator
# Starts WSL + Wazuh + updates portproxy + opens dashboard

Write-Host "=== Starting SOC Lab (Wazuh) ===" -ForegroundColor Cyan

# 1. Check WSL
Write-Host "[1/6] Checking WSL..." -ForegroundColor Yellow
$wslCheck = wsl -d Ubuntu echo "ok" 2>$null
if (-not $wslCheck) {
    Write-Host "ERROR: WSL not available" -ForegroundColor Red
    exit 1
}

# 2. Start Wazuh Indexer
Write-Host "[2/6] Starting Wazuh Indexer..." -ForegroundColor Yellow
wsl -d Ubuntu -u root systemctl start wazuh-indexer

Write-Host "Waiting for Indexer to become GREEN (this may take up to 3 minutes)..." -ForegroundColor Yellow
$timeout = 180 # Максимум ждем 3 минуты
$elapsed = 0
$isReady = $false

while ($elapsed -lt $timeout) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    
    # Отправляем запрос к Indexer и смотрим на статус здоровья кластера
    $status = wsl -d Ubuntu -u root curl -s -k https://127.0.0.1:9200/_cluster/health 2>$null
    
    if ($status -match '"status":"green"' -or $status -match '"status":"yellow"') {
        Write-Host "Indexer is UP and ready!" -ForegroundColor Green
        $isReady = $true
        break
    }
    Write-Host "  ... still initializing ($elapsed sec)" -ForegroundColor DarkGray
}

if (-not $isReady) {
    Write-Host "WARNING: Indexer took too long to start. Proceeding anyway..." -ForegroundColor Red
}

# 3. Start Wazuh Manager
Write-Host "[3/6] Starting Wazuh Manager..." -ForegroundColor Yellow
wsl -d Ubuntu -u root systemctl start wazuh-manager

# 4. Start Wazuh Dashboard
Write-Host "[4/6] Starting Wazuh Dashboard..." -ForegroundColor Yellow
wsl -d Ubuntu -u root systemctl start wazuh-dashboard

# Дадим Dashboard 15 секунд на подключение к уже работающему Indexer'у
Start-Sleep -Seconds 15

# 5. Check status
Write-Host "[5/6] Checking services..." -ForegroundColor Yellow
wsl -d Ubuntu -u root systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager

# 6. Update portproxy (вызываем исправленный скрипт)
Write-Host ""
Write-Host "[6/6] Updating portproxy..." -ForegroundColor Yellow
& "D:\SOC-Lab\update-portproxy.ps1"

# 7. Open dashboard
Write-Host ""
Write-Host "Opening Wazuh Dashboard..." -ForegroundColor Yellow
# Открываем 127.0.0.1, чтобы избежать проблем с IPv6 (localhost -> ::1)
Start-Process "https://127.0.0.1"

Write-Host ""
Write-Host "=== Wazuh started. Dashboard: https://127.0.0.1 ===" -ForegroundColor Green