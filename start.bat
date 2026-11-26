@echo off
echo ====================================================
echo Starting AgentGuard Backend ^& Frontend Servers...
echo ====================================================
start "AgentGuard FastAPI Backend" cmd /k "python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"
ping -n 3 127.0.0.1 >nul
start "AgentGuard React Frontend" cmd /k "cd frontend && npm run dev"
echo ====================================================
echo AgentGuard is starting!
echo Backend API: http://localhost:8000
echo Frontend Dashboard: http://localhost:3000
echo ====================================================
