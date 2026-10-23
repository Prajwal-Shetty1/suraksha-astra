from datetime import datetime, timezone
import json
from pathlib import Path

from backend.database import accounts_collection


# Profile fields for newly created accounts.
# None means the information is not available yet.
DEFAULT_ACCOUNT = {
    "account_age_minutes": None,
    "followers_count": None,
    "following_count": None,
    "posts_count": None,
    "devices": None,
    "locations": None,
    "username_history": None,
}


def normalize_username(username: str) -> str:
    """Trim whitespace and validate the username."""
    return (username or "").strip()


def get_account(username: str):
    """Retrieve an account from MongoDB, or return None if absent."""
    username = normalize_username(username)

    if not username:
        return None

    return accounts_collection.find_one(
        {"username": username},
        {"_id": 0},
    )


def create_account(username: str) -> dict:
    """Create a basic profile if the username does not already exist."""
    username = normalize_username(username)

    if not username:
        raise ValueError("Username cannot be empty")

    # Preserve an existing account and its saved details.
    existing = get_account(username)

    if existing is not None:
        return existing

    account = {
        "username": username,
        **DEFAULT_ACCOUNT,
        "created_at": datetime.now(timezone.utc),
        "profile_source": "application-created",
    }

    accounts_collection.update_one(
        {"username": username},
        {"$setOnInsert": account},
        upsert=True,
    )

    # Return the stored account.
    saved_account = get_account(username)

    if saved_account is None:
        raise RuntimeError("Failed to create the account in MongoDB")

    return saved_account


def migrate_accounts() -> int:
    """
    Import predefined demonstration accounts from accounts_db.json.

    Existing MongoDB accounts are not overwritten.
    """
    project_root = Path(__file__).resolve().parent.parent
    json_db_path = project_root / "backend" / "accounts_db.json"

    if not json_db_path.exists():
        raise FileNotFoundError(
            f"Account file not found: {json_db_path}"
        )

    with open(json_db_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "accounts_db.json must contain a JSON object of accounts"
        )

    for username, account_data in data.items():
        username = normalize_username(username)

        if not username:
            continue

        account = dict(account_data)
        account["username"] = username

        accounts_collection.update_one(
            {"username": username},
            {"$setOnInsert": account},
            upsert=True,
        )

    return len(data)

