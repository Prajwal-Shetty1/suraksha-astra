import json
from pathlib import Path

from backend.database import accounts_collection

PROJECT_ROOT = Path(__file__).resolve().parent.parent
JSON_DB_PATH = PROJECT_ROOT / "backend" / "accounts_db.json"


def migrate_accounts():
    """Import sample accounts from JSON into MongoDB."""
    if not JSON_DB_PATH.exists():
        raise FileNotFoundError(f"Account file not found: {JSON_DB_PATH}")

    with open(JSON_DB_PATH, "r", encoding="utf-8") as file:
        data = json.load(file)

    for username, account in data.items():
        accounts_collection.update_one(
            {"username": username},
            {"$set": account},
            upsert=True
        )

    return len(data)


def get_account(username):
    """Retrieve one account from MongoDB."""
    return accounts_collection.find_one(
        {"username": username},
        {"_id": 0}
    )