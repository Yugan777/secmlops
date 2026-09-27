from detection.risk_engine import RiskEngine
from agent.security_agent import SecurityAgent
from policy.safety_gate import PolicySafetyGate
from containment.kubernetes_containment import KubernetesContainment


class SecMLOpsPipeline:

    def __init__(self):
        self.risk_engine = RiskEngine()
        self.agent = SecurityAgent()
        self.safety_gate = PolicySafetyGate()
        self.containment = KubernetesContainment()

    def process_detection(self, detection):

        # ---------------------------------------------------------
        # 1. Calculate risk
        # ---------------------------------------------------------

        risk = self.risk_engine.calculate_risk(detection)

        # ---------------------------------------------------------
        # 2. Security agent analyzes the detection
        # ---------------------------------------------------------

        agent_result = self.agent.analyze(
            detection,
            risk
        )

        # ---------------------------------------------------------
        # 3. Policy safety gate validates the action
        # ---------------------------------------------------------

        gate_result = self.safety_gate.evaluate(
            agent_result
        )

        # ---------------------------------------------------------
        # 4. Execute approved containment
        # ---------------------------------------------------------

        containment_result = None

        if (
            gate_result["approved"]
            and gate_result["action"] == "ISOLATE_POD"
        ):
            containment_result = self.containment.isolate_pod(
                detection.get("namespace"),
                detection.get("pod")
            )

        # ---------------------------------------------------------
        # 5. Return complete pipeline result
        # ---------------------------------------------------------

        return {
            "detection": detection,
            "risk": risk,
            "agent": agent_result,
            "policy": gate_result,
            "containment": containment_result
        }


if __name__ == "__main__":

    # -------------------------------------------------------------
    # Synthetic detection for integration testing
    # -------------------------------------------------------------

    sample_detection = {
        "detected": True,
        "attack_type": "MULTI_STAGE_ACTIVITY",
        "confidence": 0.8,
        "pod": "telemetry-test",
        "namespace": "security-lab",
        "file": "/tmp/secmlops-test/sensitive.txt",
        "destination_ip": "10.0.0.50",
        "time_window_seconds": 2.0,
        "processes": [
            {
                "process": "/bin/sh",
                "timestamp": "2026-09-25T18:20:01Z"
            },
            {
                "process": "/bin/cat",
                "timestamp": "2026-09-25T18:20:03Z"
            },
            {
                "process": "/bin/wget",
                "timestamp": "2026-09-25T18:20:04Z"
            }
        ]
    }

    # -------------------------------------------------------------
    # Run pipeline
    # -------------------------------------------------------------

    pipeline = SecMLOpsPipeline()

    result = pipeline.process_detection(
        sample_detection
    )

    # -------------------------------------------------------------
    # Display result
    # -------------------------------------------------------------

    print("\n========== SEC MLOPS PIPELINE ==========")

    print("\n[1] DETECTION")

    print(
        f"Attack Type : "
        f"{result['detection']['attack_type']}"
    )

    print(
        f"Confidence  : "
        f"{result['detection']['confidence']}"
    )

    print("\n[2] RISK")

    print(
        f"Risk Score  : "
        f"{result['risk']['risk_score']}"
    )

    print(
        f"Severity    : "
        f"{result['risk']['severity']}"
    )

    print("\nReasons:")

    for reason in result["risk"]["reasons"]:
        print(f"  + {reason}")

    print("\n[3] SECURITY AGENT")

    print(
        f"Assessment  : "
        f"{result['agent']['assessment']}"
    )

    print(
        f"Priority    : "
        f"{result['agent']['priority']}"
    )

    print(
        f"Recommendation : "
        f"{result['agent']['recommended_action']}"
    )

    print("\nAgent Reasoning:")

    for reason in result["agent"]["reasoning"]:
        print(f"  + {reason}")

    print("\n[4] POLICY SAFETY GATE")

    print(
        f"Approved    : "
        f"{result['policy']['approved']}"
    )

    print(
        f"Action      : "
        f"{result['policy']['action']}"
    )

    print(
        f"Reason      : "
        f"{result['policy']['reason']}"
    )

    print("\n[5] CONTAINMENT")

    if result["containment"]:

        print(
            f"Success     : "
            f"{result['containment']['success']}"
        )

        print(
            f"Action      : "
            f"{result['containment']['action']}"
        )

        print(
            f"Namespace   : "
            f"{result['containment'].get('namespace', 'N/A')}"
        )

        print(
            f"Pod         : "
            f"{result['containment'].get('pod', 'N/A')}"
        )

        print(
            f"Policy      : "
            f"{result['containment'].get('policy', 'N/A')}"
        )

        print(
            f"Reason      : "
            f"{result['containment']['reason']}"
        )

    else:

        print("No containment action executed.")

    print("\n========================================")
