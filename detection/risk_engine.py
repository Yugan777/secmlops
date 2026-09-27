class RiskEngine:
    def calculate_risk(self, detection):
        score = 0
        reasons = []

        # Sensitive file access
        if detection.get("file"):
            score += 20
            reasons.append("Sensitive file access detected")

        # Network connection
        if detection.get("destination_ip"):
            score += 20
            reasons.append("Outbound network connection detected")

        # Multi-stage activity
        if detection.get("attack_type") == "MULTI_STAGE_ACTIVITY":
            score += 20
            reasons.append("Multi-stage activity detected")

        # Process chain
        processes = detection.get("processes", [])

        if len(processes) >= 2:
            score += 15
            reasons.append("Multiple processes involved in attack chain")

        # Temporal correlation
        if detection.get("time_window_seconds") is not None:
            score += 15
            reasons.append("Events correlated within temporal window")

        # Cap score at 100
        score = min(score, 100)

        # Severity
        if score >= 81:
            severity = "CRITICAL"
        elif score >= 61:
            severity = "HIGH"
        elif score >= 31:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons
        }


if __name__ == "__main__":
    # Simple standalone test
    sample_detection = {
        "attack_type": "MULTI_STAGE_ACTIVITY",
        "file": "/tmp/secmlops-test/sensitive.txt",
        "destination_ip": "10.0.0.50",
        "time_window_seconds": 2.0,
        "processes": [
            {"process": "/bin/sh"},
            {"process": "/bin/cat"},
            {"process": "/bin/wget"}
        ]
    }

    engine = RiskEngine()
    result = engine.calculate_risk(sample_detection)

    print("\n========== RISK ENGINE ==========")
    print(f"Risk Score : {result['risk_score']}")
    print(f"Severity   : {result['severity']}")

    print("\nReasons:")
    for reason in result["reasons"]:
        print(f"  + {reason}")

    print("=================================")

