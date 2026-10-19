from backend.account_database import get_account

username = "tharun_gk"

account = get_account(username)

if account:
    print("Account retrieved successfully!")
    print("Username:", account["username"])
    print("Followers:", account["followers_count"])
    print("Following:", account["following_count"])
    print("Posts:", account["posts_count"])
    print("Devices:", account["devices"])
    print("Locations:", account["locations"])
else:
    print("Account not found in MongoDB!")