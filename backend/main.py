from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import tempfile
from datetime import datetime

from backend.models import analyze_text, analyze_image
from backend.safety_score import calculate_text_score, calculate_image_score
from backend.transparency import generate_explanation
from backend.impersonation import check_impersonation
from backend.behavior import track_username_change, track_login, check_account_growth
from backend.account_database import get_account

app = FastAPI(title="Suraksha-Astra API")

user_scores = {}
admin_alerts = []


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
        "alert_id": len(admin_alerts) + 1,
        "username": username,
        "risk_score": risk_score,
        "action": action,
        "reasons": reasons,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": "Suspicious account detected. Review recommended."
    }

    admin_alerts.append(alert)


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

    return {
        "user_id": user_id,
        "content_type": "text",
        "decision": decision,
        "analysis": result,
        "safety": safety,
        "final_decision": final_decision
    }


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

    return {
        "user_id": user_id,
        "content_type": "image",
        "decision": decision,
        "analysis": result,
        "safety": safety,
        "final_decision": final_decision
    }


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

    return result


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

    return {
        "user_id": user_id,
        "event": "username_change",
        "decision": result["status"],
        "behavior_result": result,
        "safety": safety,
        "final_decision": final_decision
    }


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

    return {
        "user_id": user_id,
        "event": "login_activity",
        "decision": result["status"],
        "behavior_result": result,
        "safety": safety,
        "final_decision": final_decision
    }


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

    return {
        "user_id": user_id,
        "event": "account_growth_analysis",
        "decision": result["status"],
        "growth_result": result,
        "safety": safety,
        "final_decision": final_decision
    }


@app.get("/account-report/{username}")
def account_report(username: str):

    account = get_account(username)

    if not account:
        return {
            "found": False,
            "message": "Account not found in database"
        }

    growth = check_account_growth(
        username,
        account["account_age_minutes"],
        account["followers_count"],
        account["following_count"],
        account["posts_count"]
    )

    login_risk = 0
    login_reasons = []

    if len(account["devices"]) >= 2:
        login_risk += 20
        login_reasons.append("Multiple devices found for this account")

    if len(account["locations"]) >= 2:
        login_risk += 25
        login_reasons.append("Multiple login locations found for this account")

    username_risk = 0
    username_reasons = []

    if len(account["username_history"]) >= 3:
        username_risk += 15
        username_reasons.append("Multiple username changes detected")

    behavior_risk = login_risk + username_risk
    account_risk = growth["risk"] + behavior_risk

    final_decision = final_decision_engine(
        content_risk=0,
        behavior_risk=behavior_risk,
        account_risk=account_risk
    )

    if final_decision["final_action"] == "BLOCK":
        final_status = "HIGH RISK"
    elif final_decision["final_action"] == "LIMIT":
        final_status = "SUSPICIOUS"
    else:
        final_status = "SAFE"

    reasons = growth["reasons"] + login_reasons + username_reasons

    create_admin_alert(
        username=username,
        risk_score=final_decision["final_risk"],
        action=final_decision["final_action"],
        reasons=reasons
    )

    return {
        "found": True,
        "username": username,
        "account_details": account,
        "growth_analysis": growth,
        "login_analysis": {
            "risk": login_risk,
            "devices_count": len(account["devices"]),
            "locations_count": len(account["locations"]),
            "devices": account["devices"],
            "locations": account["locations"],
            "reasons": login_reasons if login_reasons else ["Normal login behavior"]
        },
        "username_analysis": {
            "risk": username_risk,
            "username_change_count": len(account["username_history"]),
            "username_history": account["username_history"],
            "reasons": username_reasons if username_reasons else ["Normal username behavior"]
        },
        "final_result": {
            "total_risk": final_decision["final_risk"],
            "status": final_status,
            "action": final_decision["final_action"],
            "meaning": final_decision["meaning"],
            "reasons": reasons
        },
        "final_decision": final_decision
    }


@app.get("/admin-alerts")
def get_admin_alerts():
    return {
        "total_alerts": len(admin_alerts),
        "alerts": admin_alerts
    }


@app.post("/clear-admin-alerts")
def clear_admin_alerts():
    admin_alerts.clear()

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