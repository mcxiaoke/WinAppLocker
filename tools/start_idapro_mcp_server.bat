@echo off
setlocal

:: Activate the virtual environment
call "C:\Home\Develop\venv\Scripts\activate.bat"


:: Activate the venv and run idalib-mcp
:: Using direct path to python prevents PATHEXT issues in batch files
uv run idalib-mcp --host 127.0.0.1 --port 8745

:: Optional: Keep the window open to see the output or errors
pause

endlocal
