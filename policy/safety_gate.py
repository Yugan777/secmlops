class PolicySafetyGate:

    ALLOWED_ACTIONS = {
        "NO_ACTION",
        "ISOLATE_POD"
    }

    PROTECTED_NAMESPACES = {
        "kube-system",
        "kube-public",
        "kube-node-lease"
    }

    MIN_ISOLATION_SCORE = 61

    def evaluate(self, agent_result):

        action = agent_result.get("recommended_action")
        score = agent_result.get("risk_score", 0)
        namespace = agent_result.get("namespace")
        pod = agent_result.get("pod")

        # ---------------------------------------------------------
        # Check action
        # ---------------------------------------------------------

        if action not in self.ALLOWED_ACTIONS:
            return {
                "approved": False,
                "action": "NO_ACTION",
                "reason": "Action is not allowed by security policy"
            }

        # ---------------------------------------------------------
        # NO_ACTION is always safe
        # ---------------------------------------------------------

        if action == "NO_ACTION":
            return {
                "approved": True,
                "action": "NO_ACTION",
                "reason": "Agent recommended no containment"
            }

        # ---------------------------------------------------------
        # Namespace protection
        # ---------------------------------------------------------

        if namespace in self.PROTECTED_NAMESPACES:
            return {
                "approved": False,
                "action": "NO_ACTION",
                "reason": f"Protected namespace: {namespace}"
            }

        # ---------------------------------------------------------
        # Pod must exist
        # ---------------------------------------------------------

        if not pod:
            return {
                "approved": False,
                "action": "NO_ACTION",
                "reason": "No target pod specified"
            }

        # ---------------------------------------------------------
        # Risk threshold
        # ---------------------------------------------------------

        if score < self.MIN_ISOLATION_SCORE:
            return {
                "approved": False,
                "action": "NO_ACTION",
                "reason": (
                    f"Risk score {score} is below "
                    f"isolation threshold "
                    f"{self.MIN_ISOLATION_SCORE}"
                )
            }

        # ---------------------------------------------------------
        # Approved
        # ---------------------------------------------------------

        return {
            "approved": True,
            "action": "ISOLATE_POD",
            "reason": (
                f"Risk score {score} meets isolation threshold "
                f"and target namespace is permitted"
            )
        }


if __name__ == "__main__":

    sample_agent_result = {
        "assessment": "High-confidence multi-stage suspicious activity",
        "risk_score": 90,
        "priority": "CRITICAL",
        "recommended_action": "ISOLATE_POD",
        "pod": "telemetry-test",
        "namespace": "security-lab"
    }

    gate = PolicySafetyGate()

    result = gate.evaluate(sample_agent_result)

    print("\n========== POLICY SAFETY GATE ==========")
    print(f"Approved : {result['approved']}")
    print(f"Action   : {result['action']}")
    print(f"Reason   : {result['reason']}")
    print("=========================================")

