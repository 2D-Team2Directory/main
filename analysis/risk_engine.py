def calculate_risk(event, normalized: dict, detection: dict) -> dict:
    score = 0

    event_type = normalized.get("event_type")
    is_privileged = normalized.get("is_privileged")
    is_off_hours = normalized.get("is_off_hours")
    detected = detection.get("detected", False)

    if event_type == "login_failure":
        score += 20
    elif event_type == "login_success":
        score += 10
    elif event_type == "group_change":
        score += 60
    elif event_type == "kerberos_request":
        score += 40

    if is_privileged:
        score += 20

    if is_off_hours:
        score += 15

    if detected:
        score += 25

    if score >= 80:
        severity = "high"
    elif score >= 50:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "none"

    return {
        "base_score": score,
        "weight": 1,
        "final_score": score,
        "severity": severity,
    }