import os
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

MONGODB_URI = os.getenv("MONGODB_URI")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is missing from .env")

client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=5000
)

db = client["suraksha_astra"]

accounts_collection = db["accounts"]
analysis_collection = db["analysis_results"]
user_scores_collection = db["user_scores"]
admin_alerts_collection = db["admin_alerts"]


def check_database_connection():
    client.admin.command("ping")
    return True