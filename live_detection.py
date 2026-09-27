import json
import subprocess
from collections import deque
from datetime import datetime, timezone
from detection.risk_engine import RiskEngine
from agent.security_agent import SecurityAgent
from policy.safety_gate import PolicySafetyGate
from containment.kubernetes_containment import KubernetesContainment
from collector.tetragon_collector import normalize_event
from detection.temporal_detector import TemporalDetector
from context.context_validator import ContextValidator
from graph.temporal_graph import TemporalSecurityGraph
from gnn.runtime import GNNRuntime

WINDOW_SECONDS = 10

detector = TemporalDetector(time_window_seconds=WINDOW_SECONDS)
risk_engine = RiskEngine()
security_agent = SecurityAgent()
safety_gate = PolicySafetyGate()
containment = KubernetesContainment()
context_validator = ContextValidator(
    temporal_threshold=WINDOW_SECONDS
)

graph = TemporalSecurityGraph(max_age_seconds=300)
gnn_runtime = GNNRuntime()

event_buffer = deque()
detected_threats = set()

def parse_timestamp(timestamp):
    return datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )


def cleanup_old_events(now):
    while event_buffer:
        oldest = parse_timestamp(event_buffer[0]["timestamp"])

        if (now - oldest).total_seconds() > WINDOW_SECONDS:
            event_buffer.popleft()
        else:
            break


def process_event(event):
    if event["event_type"] == "UNKNOWN":
        return

    graph.add_event(event)

    now = parse_timestamp(event["timestamp"])

    event_buffer.append(event)
    cleanup_old_events(now)

    events = list(event_buffer)

    detection = detector.detect(events)

    print(
        f"[EVENT] {event['event_type']} | "
        f"{event.get('process')} | "
        f"{event.get('file_path', event.get('destination_ip', ''))}"
    )

    if detection:

        threat_key = (
            detection.get("pod"),
            detection.get("file"),
            detection.get("destination_ip"),
            detection.get("attack_type"),
        )

        if threat_key not in detected_threats:
            detected_threats.add(threat_key)

            context = context_validator.validate(detection)
            detection["context"] = context

            gnn_result = gnn_runtime.predict(detection)
            detection["gnn"] = gnn_result

            print("\nTEMPORAL GNN")
            print("-" * 60)
            print(
                 f"Available            : "
                 f"{gnn_result['available']}"
            )
            print(
                 f"Benign Probability   : "
                 f"{gnn_result.get('benign_probability', 0.0)}"
            )
            print(
                 f"Suspicious Probability: "
                 f"{gnn_result.get('suspicious_probability', 0.0)}"
            )
            print(
                 f"Prediction           : "
                 f"{gnn_result['prediction']}"
            )

            print("\nCONTEXT VALIDATION")
            print(f"Validated          : {context['validated']}")
            print(f"Context Score      : {context['context_score']}")
            print(f"Same Workload      : {context['same_workload']}")
            print(f"Process Ancestry   : {context['process_ancestry']}")
            print(f"Temporal Proximity : {context['temporal_proximity']}")
            print(f"Sensitive Resource : {context['sensitive_resource']}")
            print(f"Network Follow-up  : {context['network_followup']}")
            print(f"Sequence Consistent: {context['sequence_consistent']}")

            print("\nContext Evidence:")
            for evidence in context["evidence"]:
                print(f"  + {evidence}")

            risk = risk_engine.calculate_risk(detection)

            print("\n" + "=" * 60)
            print("THREAT DETECTED")
            print("=" * 60)
            print(json.dumps(detection, indent=2))

            print("\nRISK ASSESSMENT")
            print("-" * 60)
            print(f"Risk Score : {risk['risk_score']}")
            print(f"Severity   : {risk['severity']}")

            print("Reasons:")
            for reason in risk["reasons"]:
                print(f"  + {reason}")

            agent_result = security_agent.analyze(detection, risk)

            print("\nSECURITY AGENT")
            print("-" * 60)
            print(f"Assessment         : {agent_result['assessment']}")
            print(f"Priority           : {agent_result['priority']}")
            print(f"Recommended Action : {agent_result['recommended_action']}")

            print("Agent Reasoning:")
            for reason in agent_result["reasoning"]:
                print(f"  + {reason}")

            policy_result = safety_gate.evaluate(agent_result)

            print("\nPOLICY SAFETY GATE")
            print("-" * 60)
            print(f"Approved : {policy_result['approved']}")
            print(f"Action   : {policy_result['action']}")
            print(f"Reason   : {policy_result['reason']}")

            if (
                policy_result["approved"]
                and policy_result["action"] == "ISOLATE_POD"
            ):
                containment_result = containment.isolate_pod(
                    detection["namespace"],
                    detection["pod"],
                )

                print("\nCONTAINMENT")
                print("-" * 60)
                print(f"Success   : {containment_result['success']}")
                print(f"Action    : {containment_result['action']}")
                print(f"Namespace : {containment_result['namespace']}")
                print(f"Pod       : {containment_result['pod']}")
                print(f"Policy    : {containment_result['policy']}")
                print(f"Reason    : {containment_result['reason']}")

            print("=" * 60 + "\n")
def main():
    print("[SecMLOps] Starting live detection pipeline...")
    print("[SecMLOps] Waiting for Tetragon events...\n")

    command = [
        "kubectl",
        "logs",
        "-n",
        "kube-system",
        "-l",
        "app.kubernetes.io/name=tetragon",
        "-c",
        "export-stdout",
        "-f",
        "--since=10s",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    for line in process.stdout:
        line = line.strip()

        if not line:
            continue

        try:
            raw_event = json.loads(line)
            event = normalize_event(raw_event)

            process_event(event)

        except json.JSONDecodeError:
            continue

        except Exception as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
