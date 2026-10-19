from backend.database import check_database_connection

try:
    check_database_connection()
    print("✅ MongoDB connected successfully!")
except Exception as error:
    print("❌ MongoDB connection failed:", error)