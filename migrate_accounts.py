from backend.account_database import migrate_accounts

try:
    count = migrate_accounts()
    print(f"Successfully migrated {count} accounts to MongoDB!")
except Exception as error:
    print("Account migration failed:", error)