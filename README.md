venv\Scripts\python.exe -m pip install -r backend\requirements.txt

venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 3000 --reload --env-file backend\.env

http://localhost:3000/docs