from pathlib import Path
from dotenv import load_dotenv
import uvicorn

if __name__ == '__main__':
    load_dotenv(Path(__file__).resolve().parents[1] / '.env.local',override=False)
    uvicorn.run('app.main:app',host='127.0.0.1',port=8000,workers=1)
