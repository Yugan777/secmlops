class SecurityAgent:
    """
    Constrained security-response agent.

    The agent analyzes structured detection and risk information
    and recommends one of the predefined actions.
    """

    ALLOWED_ACTIONS = {
        "NO_ACTION",
        "ISOLATE_POD"
    }

    def analyze(self, detection, risk):
        score = risk.get("risk_score", 0)
        reasons = risk.get("reasons", [])

        # Default safe action
        recommended_action = "NO_ACTION"

        if score >= 61:
            recommended_action = "ISOLATE_POD"

        # Never allow an undefined action
        if recommended_action not in self.ALLOWED_ACTIONS:
            recommended_action = "NO_ACTION"

        if score >= 81:
            priority = "CRITICAL"
            assessment = "High-confidence multi-stage suspicious activity"
        elif score >= 61:
            priority = "HIGH"
            assessment = "Suspicious activity requiring containment review"
        elif score >= 31:
            priority = "MEDIUM"
            assessment = "Potentially suspicious activity"
        else:
            priority = "LOW"
            assessment = "Low-risk activity"

        reasoning = []

        for reason in reasons:
            reasoning.append(reason)

        return {
            "assessment": assessment,
            "reasoning": reasoning,
            "recommended_action": recommended_action,
            "priority": priority,
            "risk_score": score,
            "pod": detection.get("pod"),
            "namespace": detection.get("namespace")
        }


if __name__ == "__main__":

    sample_detection = {
        "attack_type": "MULTI_STAGE_ACTIVITY",
        "file": "/tmp/secmlops-test/sensitive.txt",
        "destination_ip": "10.0.0.50",
        "time_window_seconds": 2.0,
        "pod": "telemetry-test",
        "namespace": "security-lab",
        "processes": [
            {"process": "/bin/sh"},
            {"process": "/bin/cat"},
            {"process": "/bin/wget"}
        ]
    }

    sample_risk = {
        "risk_score": 90,
        "severity": "CRITICAL",
        "reasons": [
            "Sensitive file access detected",
            "Outbound network connection detected",
            "Multi-stage activity detected",
            "Multiple processes involved in attack chain",
            "Events correlated within temporal window"
        ]
    }

    agent = SecurityAgent()

    result = agent.analyze(
        sample_detection,
        sample_risk
    )

    print("\n========== SECURITY AGENT ==========")
    print(f"Assessment        : {result['assessment']}")
    print(f"Risk Score        : {result['risk_score']}")
    print(f"Priority          : {result['priority']}")
    print(f"Recommended Action: {result['recommended_action']}")

    print("\nReasoning:")
    for reason in result["reasoning"]:
        print(f"  + {reason}")

    print(f"\nPod       : {result['pod']}")
    print(f"Namespace : {result['namespace']}")
    print("====================================")

