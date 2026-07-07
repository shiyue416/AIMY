@echo off
set port=65445
set jar=%TEMP%\t.txt

echo Step 1: Login with test:test
curl -s -c %jar% -X POST http://localhost:%port%/ -d username=test
echo.

echo Step 2: Submit password
curl -s -L -b %jar% -c %jar% -X POST http://localhost:%port%/password/test -d "username=test&password=test"
echo.

echo Step 3: Get receipt
curl -s -b %jar% http://localhost:%port%/order/300401/receipt
echo.

pause
