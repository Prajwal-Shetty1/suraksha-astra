from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import tempfile
from datetime import datetime, timezone
from collections.abc import MutableMapping
from backend.database import user_scores_collection, admin_alerts_collection, analysis_collection

from backend.models import analyze_text, analyze_image
from backend.safety_score import calculate_text_score, calculate_image_score
from backend.transparency import generate_explanation
from backend.impersonation import check_impersonation
from backend.behavior import track_username_change, track_login, check_account_growth
from backend.account_database import get_account, create_account

app = FastAPI(title="Suraksha-Astra API")

class MongoUserScores(MutableMapping):
    """Mongo-backed scores, preserving existing endpoint syntax."""
    def __getitem__(self, key):
        record = user_scores_collection.find_one({"user_id": key})
        if record is None:
            raise KeyError(key)
        return record["score"]

    def __setitem__(self, key, value):
        user_scores_collection.update_one(
            {"user_id": key},
            {"$set": {"score": value, "updated_at": datetime.now(timezone.utc)}},
            upsert=True,
        )

    def __delitem__(self, key):
        result = user_scores_collection.delete_one({"user_id": key})
        if not result.deleted_count:
            raise KeyError(key)

    def __iter__(self):
        return (record["user_id"] for record in user_scores_collection.find({}, {"user_id": 1}))

    def __len__(self):
        return user_scores_collection.count_documents({})

    def __contains__(self, key):
        return user_scores_collection.find_one({"user_id": key}, {"_id": 1}) is not None


user_scores = MongoUserScores()


def save_analysis(payload):
    """Persist each activity with a searchable user_id and timestamp."""
    created_at = datetime.now(timezone.utc)
    payload.setdefault("created_at", created_at.isoformat())
    event = payload.get("event") or payload.get("content_type") or "analysis"
    analysis_collection.insert_one({
        "created_at": created_at,
        "user_id": payload.get("user_id"),
        "event": event,
        "result": payload,
    })
    return payload


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "Suraksha-Astra running"}


def final_decision_engine(content_risk=0, behavior_risk=0, account_risk=0):
    final_risk = content_risk + behavior_risk + account_risk

    if final_risk >= 70:
        final_action = "BLOCK"
        meaning = "High cyber safety risk. Action should be blocked."
    elif final_risk >= 40:
        final_action = "LIMIT"
        meaning = "Moderate risk. Account/action should be limited or reviewed."
    else:
        final_action = "ALLOW"
        meaning = "Low risk. Action can be allowed."

    return {
        "content_risk": content_risk,
        "behavior_risk": behavior_risk,
        "account_risk": account_risk,
        "final_risk": final_risk,
        "final_action": final_action,
        "meaning": meaning
    }


def create_admin_alert(username, risk_score, action, reasons):
    if action not in ["LIMIT", "BLOCK"]:
        return

    alert = {
        "alert_id": None,
        "username": username,
        "risk_score": risk_score,
        "action": action,
        "reasons": reasons,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": "Suspicious account detected. Review recommended."
    }

    inserted = admin_alerts_collection.insert_one(alert)
    admin_alerts_collection.update_one({"_id": inserted.inserted_id}, {"$set": {"alert_id": str(inserted.inserted_id)}})


def scam_keyword_boost(text: str):
    text_lower = text.lower()

    scam_keywords = [
        "otp",
        "bank",
        "account",
        "password",
        "urgent",
        "transfer",
        "verify",
        "click",
        "link",
        "payment",
        "kyc",
        "upi",
        "gpay",
        "phonepe",
        "paytm",
        "pin",
        "cvv",
        "card",
        "login",
        "blocked",
        "update"
    ]

    scam_boost = 0
    scam_reasons = []

    for word in scam_keywords:
        if word in text_lower:
            scam_boost += 0.15
            scam_reasons.append(f"Suspicious scam keyword detected: {word}")

    if "send otp" in text_lower:
        scam_boost += 0.35
        scam_reasons.append("High-risk phrase detected: send otp")

    if "account blocked" in text_lower:
        scam_boost += 0.35
        scam_reasons.append("High-risk phrase detected: account blocked")

    if "click link" in text_lower:
        scam_boost += 0.35
        scam_reasons.append("High-risk phrase detected: click link")

    if "verify kyc" in text_lower or "kyc update" in text_lower:
        scam_boost += 0.35
        scam_reasons.append("High-risk KYC scam pattern detected")

    return min(scam_boost, 1.0), scam_reasons


@app.post("/check-text")
def check_text(text: str, user_id: str = "default_user"):

    if user_id not in user_scores:
        user_scores[user_id] = 100

    result = analyze_text(text)

    scam_boost, scam_reasons = scam_keyword_boost(text)
    result["scam"] = min(result.get("scam", 0) + scam_boost, 1.0)

    score, reasons = calculate_text_score(result, user_scores[user_id])
    reasons.extend(scam_reasons)

    user_scores[user_id] = score
    safety = generate_explanation(score, reasons)

    content_risk = 100 - score
    account_risk = 100 - user_scores[user_id]

    if result["scam"] > 0.6 or result["threat"] > 0.6:
        decision = "BLOCKED"
    elif result["scam"] > 0.3 or result["toxicity"] > 0.4 or result["insult"] > 0.5:
        decision = "SUSPICIOUS"
    else:
        decision = "ALLOWED"

    final_decision = final_decision_engine(
        content_risk=content_risk,
        behavior_risk=0,
        account_risk=account_risk
    )

    create_admin_alert(
        username=user_id,
        risk_score=final_decision["final_risk"],
        action=final_decision["final_action"],
        reasons=reasons
    )

    return save_analysis({
        "user_id": user_id,
        "content_type": "text",
        "decision": decision,
        "analysis": result,
        "safety": safety,
        "final_decision": final_decision
    })


@app.post("/check-image")
async def check_image(file: UploadFile = File(...), user_id: str = "default_user"):

    if user_id not in user_scores:
        user_scores[user_id] = 100

    content = await file.read()

    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
    temp.write(content)
    temp.close()

    result = analyze_image(temp.name, content)

    score, reasons = calculate_image_score(result, user_scores[user_id])
    user_scores[user_id] = score

    safety = generate_explanation(score, reasons)

    content_risk = 100 - score
    account_risk = 100 - user_scores[user_id]

    if result["nudity_score"] > 0.6:
        decision = "BLOCKED"
    elif result["skin_exposure_score"] > 0.25 or result["deepfake_score"] > 0.5:
        decision = "SUSPICIOUS"
    else:
        decision = "ALLOWED"

    final_decision = final_decision_engine(
        content_risk=content_risk,
        behavior_risk=0,
        account_risk=account_risk
    )

    create_admin_alert(
        username=user_id,
        risk_score=final_decision["final_risk"],
        action=final_decision["final_action"],
        reasons=reasons
    )

    return save_analysis({
        "user_id": user_id,
        "content_type": "image",
        "decision": decision,
        "analysis": result,
        "safety": safety,
        "final_decision": final_decision
    })


@app.post("/check-impersonation")
def check_profile_impersonation(
    original_username: str,
    suspicious_username: str,
    original_bio: str,
    suspicious_bio: str
):
    result = check_impersonation(
        original_username,
        suspicious_username,
        original_bio,
        suspicious_bio
    )

    return save_analysis({"event": "impersonation_check", "result": result})["result"]


@app.post("/track-username")
def track_username(user_id: str, new_username: str):

    if user_id not in user_scores:
        user_scores[user_id] = 100

    result = track_username_change(user_id, new_username)

    if result["risk"] > 0:
        user_scores[user_id] = max(user_scores[user_id] - result["risk"], 0)

    safety = generate_explanation(user_scores[user_id], result["reasons"])

    final_decision = final_decision_engine(
        content_risk=0,
        behavior_risk=result["risk"],
        account_risk=100 - user_scores[user_id]
    )

    create_admin_alert(
        username=user_id,
        risk_score=final_decision["final_risk"],
        action=final_decision["final_action"],
        reasons=result["reasons"]
    )

    return save_analysis({
        "user_id": user_id,
        "event": "username_change",
        "decision": result["status"],
        "behavior_result": result,
        "safety": safety,
        "final_decision": final_decision
    })


@app.post("/track-login")
def track_user_login(user_id: str, device_id: str, location: str):

    if user_id not in user_scores:
        user_scores[user_id] = 100

    result = track_login(user_id, device_id, location)

    if result["risk"] > 0:
        user_scores[user_id] = max(user_scores[user_id] - result["risk"], 0)

    safety = generate_explanation(user_scores[user_id], result["reasons"])

    final_decision = final_decision_engine(
        content_risk=0,
        behavior_risk=result["risk"],
        account_risk=100 - user_scores[user_id]
    )

    create_admin_alert(
        username=user_id,
        risk_score=final_decision["final_risk"],
        action=final_decision["final_action"],
        reasons=result["reasons"]
    )

    return save_analysis({
        "user_id": user_id,
        "event": "login_activity",
        "decision": result["status"],
        "behavior_result": result,
        "safety": safety,
        "final_decision": final_decision
    })


@app.post("/check-growth")
def check_growth(
    user_id: str,
    account_age_minutes: int,
    followers_count: int,
    following_count: int,
    posts_count: int
):

    if user_id not in user_scores:
        user_scores[user_id] = 100

    result = check_account_growth(
        user_id,
        account_age_minutes,
        followers_count,
        following_count,
        posts_count
    )

    if result["risk"] > 0:
        user_scores[user_id] = max(user_scores[user_id] - result["risk"], 0)

    safety = generate_explanation(user_scores[user_id], result["reasons"])

    final_decision = final_decision_engine(
        content_risk=0,
        behavior_risk=result["risk"],
        account_risk=100 - user_scores[user_id]
    )

    create_admin_alert(
        username=user_id,
        risk_score=final_decision["final_risk"],
        action=final_decision["final_action"],
        reasons=result["reasons"]
    )

    return save_analysis({
        "user_id": user_id,
        "event": "account_growth_analysis",
        "decision": result["status"],
        "growth_result": result,
        "safety": safety,
        "final_decision": final_decision
    })


@app.get("/account-report/{username}")
def account_report(username: str):
    """
    Return the account report using the current safety score and available
    profile signals. A blocked individual upload does not automatically mean
    the whole account must be blocked; upload decisions remain in activity history.
    """
    username = (username or "").strip()
    if not username:
        return {"found": False, "message": "Username cannot be empty"}

    account = get_account(username)
    if account is None:
        account = create_account(username)

    activity_cursor = analysis_collection.find({
        "$or": [{"user_id": username}, {"result.user_id": username}],
        "event": {"$ne": "account_report"},
        "result.event": {"$ne": "account_report"},
    }).sort("created_at", -1).limit(50)

    activity_history = []
    scan_reasons = []
    for item in activity_cursor:
        result = item.get("result") or {}
        safety = result.get("safety") or {}
        final_decision_data = result.get("final_decision") or {}
        final_result = result.get("final_result") or {}
        event = (
            item.get("event")
            or result.get("event")
            or result.get("content_type")
            or "analysis"
        )
        decision = str(
            result.get("decision")
            or final_decision_data.get("final_action")
            or final_result.get("status")
            or "ANALYZED"
        ).upper()
        final_action = str(
            final_decision_data.get("final_action")
            or final_result.get("action")
            or ""
        ).upper()
        score = safety.get("score")

        # Preserve individual scan outcomes for the history/reasons.
        # Do not force account-level risk to 70 just because one upload was blocked.
        if event in ("text", "image") or result.get("content_type") in ("text", "image"):
            if decision in ("BLOCKED", "BLOCK") or final_action == "BLOCK":
                scan_reasons.append(f"{str(event).title()} scan was blocked")
            elif decision == "SUSPICIOUS" or final_action == "LIMIT":
                scan_reasons.append(f"{str(event).title()} scan was suspicious")

        activity_history.append({
            "event": event,
            "created_at": item.get("created_at"),
            "decision": decision,
            "safety_score": score,
            "final_action": final_action or None,
        })

    age = account.get("account_age_minutes")
    followers = account.get("followers_count")
    following = account.get("following_count")
    posts = account.get("posts_count")
    devices = account.get("devices")
    locations = account.get("locations")
    username_history = account.get("username_history")

    growth_available = all(
        value is not None for value in (age, followers, following, posts)
    )
    if growth_available:
        growth = check_account_growth(username, age, followers, following, posts)
        growth_risk = int(growth.get("risk") or 0)
        growth_reasons = growth.get("reasons", [])
    else:
        growth = {
            "account_age_minutes": age,
            "followers_count": followers,
            "following_count": following,
            "posts_count": posts,
            "risk": None,
            "reasons": ["Growth information is not available."],
            "available": False,
        }
        growth_risk = 0
        growth_reasons = growth["reasons"]

    login_risk = None
    login_reasons = []
    if devices is not None and locations is not None:
        login_risk = 0
        if len(devices) >= 2:
            login_risk += 20
            login_reasons.append("Multiple devices found for this account")
        if len(locations) >= 2:
            login_risk += 25
            login_reasons.append("Multiple login locations found for this account")
        if not login_reasons:
            login_reasons.append("No configured login risk indicators detected")
    else:
        login_reasons.append("Login device/location information is not available.")

    username_risk = None
    username_reasons = []
    if username_history is not None:
        username_risk = 15 if len(username_history) >= 3 else 0
        username_reasons.append(
            "Multiple username changes detected"
            if username_risk
            else "No configured username-history risk indicators detected"
        )
    else:
        username_reasons.append("Username history is not available.")

    # Current safety score is the cumulative score already updated by scans.
    # Convert it to risk once; don't add the same scan risk again.
    current_safety_score = int(user_scores.get(username, 100))
    score_risk = max(0, min(100, 100 - current_safety_score))

    profile_risks = [growth_risk]
    if login_risk is not None:
        profile_risks.append(login_risk)
    if username_risk is not None:
        profile_risks.append(username_risk)
    profile_risk = min(100, sum(profile_risks))

    # Use the strongest signal, avoiding double-counting score and scan history.
    total_risk = max(score_risk, profile_risk)

    if total_risk >= 70:
        action, status = "BLOCK", "HIGH RISK"
        meaning = "High overall account risk. Block account activity and review."
    elif total_risk >= 40:
        action, status = "LIMIT", "SUSPICIOUS"
        meaning = "Moderate overall account risk. Limit activity and review."
    else:
        action, status = "ALLOW", "SAFE"
        meaning = "Overall account risk is low. Individual unsafe uploads can still be blocked."

    reasons = []
    if score_risk > 0:
        reasons.append(
            f"Current safety score is {current_safety_score}/100 "
            f"(score-derived risk: {score_risk}/100)."
        )
    reasons.extend(scan_reasons)
    if growth_available:
        reasons.extend(growth_reasons)
    else:
        reasons.append(
            "Profile growth data is unavailable; the report uses the current safety score "
            "and available account signals."
        )
    if login_risk is not None:
        reasons.extend(login_reasons)
    if username_risk is not None:
        reasons.extend(username_reasons)
    if not reasons:
        reasons.append("No suspicious scan or configured profile indicators detected.")

    final_decision = {
        "content_risk": score_risk,
        "behavior_risk": (login_risk or 0) + (username_risk or 0),
        "account_risk": growth_risk,
        "final_risk": total_risk,
        "final_action": action,
        "meaning": meaning,
    }

    return {
        "found": True,
        "event": "account_report",
        "user_id": username,
        "username": username,
        "current_safety_score": current_safety_score,
        "activity_history": activity_history,
        "account_details": account,
        "growth_analysis": growth,
        "login_analysis": {
            "risk": login_risk,
            "devices_count": len(devices) if devices is not None else None,
            "locations_count": len(locations) if locations is not None else None,
            "devices": devices,
            "locations": locations,
            "reasons": login_reasons,
        },
        "username_analysis": {
            "risk": username_risk,
            "username_change_count": (
                len(username_history) if username_history is not None else None
            ),
            "username_history": username_history,
            "reasons": username_reasons,
        },
        "final_result": {
            "total_risk": total_risk,
            "status": status,
            "action": action,
            "meaning": meaning,
            "reasons": reasons,
        },
        "final_decision": final_decision,
    }


@app.get("/admin-alerts")
def get_admin_alerts():
    alerts = list(admin_alerts_collection.find().sort("_id", -1))
    for alert in alerts:
        alert["_id"] = str(alert["_id"])
    return {"total_alerts": len(alerts), "alerts": alerts}


@app.post("/clear-admin-alerts")
def clear_admin_alerts():
    admin_alerts_collection.delete_many({})

    return {
        "message": "Admin alerts cleared successfully"
    }


@app.get("/user-score/{user_id}")
def get_user_score(user_id: str):

    score = user_scores.get(user_id, 100)
    safety = generate_explanation(score, [])

    return {
        "user_id": user_id,
        "safety": safety
    }


@app.post("/reset-score/{user_id}")
def reset_user_score(user_id: str):

    user_scores[user_id] = 100

    return {
        "message": "User safety score reset successfully",
        "user_id": user_id,
        "score": 100
    }