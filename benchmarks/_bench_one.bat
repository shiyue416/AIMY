@echo off
cd /d C:\Users\PC\Desktop\validation-benchmarks\benchmarks\XBEN-001-24
echo Building + starting...
docker compose build --build-arg FLAG=test_flag >nul 2>&1
docker compose up -d >nul 2>&1
timeout /t 6 /nobreak >nul

REM Get port: 0.0.0.0:PORT->80/tcp
for /f "tokens=2 delims=:" %%a in ('docker ps --filter "name=xben-001" --format "{{.Ports}}"') do set "p=%%a"
for /f "delims=-" %%b in ("%p%") do set port=%%b
echo Port: %port%

echo.
echo Login...
curl -s -c %TEMP%\c.txt -X POST http://localhost:%port%/ -d username=test >nul
curl -s -L -b %TEMP%\c.txt -c %TEMP%\c.txt -X POST http://localhost:%port%/password/test -d "username=test&password=test" >nul

echo Receipt:
curl -s -b %TEMP%\c.txt http://localhost:%port%/order/300401/receipt
echo.
docker compose down -v >nul 2>&1
pause
