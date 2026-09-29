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


# ============================================================
# CONFIGURATION
# ============================================================

WINDOW_SECONDS = 10
STATE_FILE = "dashboard/live_state.json"


# ============================================================
# COMPONENTS
# ============================================================

detector = TemporalDetector(
    time_window_seconds=WINDOW_SECONDS
)

risk_engine = RiskEngine()

security_agent = SecurityAgent()

safety_gate = PolicySafetyGate()

containment = KubernetesContainment()

context_validator = ContextValidator(
    temporal_threshold=WINDOW_SECONDS
)

graph = TemporalSecurityGraph(
    max_age_seconds=300
)

gnn_runtime = GNNRuntime()


# ============================================================
# RUNTIME STATE
# ============================================================

event_buffer = deque()

detected_threats = set()


# ============================================================
# TIMESTAMP
# ============================================================

def parse_timestamp(timestamp):

    return datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )


# ============================================================
# EVENT CLEANUP
# ============================================================

def cleanup_old_events(now):

    while event_buffer:

        oldest = parse_timestamp(
            event_buffer[0]["timestamp"]
        )

        if (
            now - oldest
        ).total_seconds() > WINDOW_SECONDS:

            event_buffer.popleft()

        else:

            break


# ============================================================
# DASHBOARD STATE
# ============================================================

def get_current_events():

    events = []

    for event in list(event_buffer)[-50:]:

        events.append({

            "event_type":
                event.get("event_type"),

            "process":
                event.get("process"),

            "file_path":
                event.get("file_path"),

            "destination_ip":
                event.get("destination_ip"),

            "timestamp":
                event.get("timestamp")

        })

    return events


def write_dashboard_state(state):

    try:

        state["updated_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        with open(
            STATE_FILE,
            "w"
        ) as f:

            json.dump(
                state,
                f,
                indent=2
            )

    except Exception as e:

        print(
            f"[DASHBOARD STATE ERROR] {e}"
        )


def write_monitoring_state():

    write_dashboard_state({

        "status": "MONITORING",

        "threat": None,

        "gnn": None,

        "context": None,

        "risk": None,

        "agent": None,

        "safety_gate": None,

        "containment": None,

        "events": get_current_events()

    })


# ============================================================
# EVENT PROCESSING
# ============================================================

def process_event(event):

    # Ignore unknown events

    if event["event_type"] == "UNKNOWN":

        return


    # --------------------------------------------------------
    # Add event to temporal graph
    # --------------------------------------------------------

    graph.add_event(event)


    # --------------------------------------------------------
    # Add event to temporal buffer
    # --------------------------------------------------------

    now = parse_timestamp(
        event["timestamp"]
    )

    event_buffer.append(event)

    cleanup_old_events(now)

    events = list(event_buffer)


    # --------------------------------------------------------
    # Temporal detection
    # --------------------------------------------------------

    detection = detector.detect(
        events
    )


    # --------------------------------------------------------
    # Print telemetry
    # --------------------------------------------------------

    print(
        f"[EVENT] {event['event_type']} | "
        f"{event.get('process')} | "
        f"{event.get('file_path', event.get('destination_ip', ''))}"
    )


    # --------------------------------------------------------
    # No detection
    # --------------------------------------------------------

    if not detection:


        return


    # --------------------------------------------------------
    # Prevent duplicate threat processing
    # --------------------------------------------------------

    threat_key = (

        detection.get("pod"),

        detection.get("file"),

        detection.get("destination_ip"),

        detection.get("attack_type")

    )


    if threat_key in detected_threats:

        return


    detected_threats.add(
        threat_key
    )


    # ========================================================
    # CONTEXT VALIDATION
    # ========================================================

    context = context_validator.validate(
        detection
    )

    detection["context"] = context


    # ========================================================
    # TEMPORAL GNN
    # ========================================================

    gnn_result = gnn_runtime.predict(
        detection
    )

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


    # ========================================================
    # CONTEXT OUTPUT
    # ========================================================

    print("\nCONTEXT VALIDATION")

    print(
        f"Validated          : "
        f"{context['validated']}"
    )

    print(
        f"Context Score      : "
        f"{context['context_score']}"
    )

    print(
        f"Same Workload      : "
        f"{context['same_workload']}"
    )

    print(
        f"Process Ancestry   : "
        f"{context['process_ancestry']}"
    )

    print(
        f"Temporal Proximity : "
        f"{context['temporal_proximity']}"
    )

    print(
        f"Sensitive Resource : "
        f"{context['sensitive_resource']}"
    )

    print(
        f"Network Follow-up  : "
        f"{context['network_followup']}"
    )

    print(
        f"Sequence Consistent: "
        f"{context['sequence_consistent']}"
    )


    print("\nContext Evidence:")

    for evidence in context["evidence"]:

        print(
            f"  + {evidence}"
        )


    # ========================================================
    # RISK ENGINE
    # ========================================================

    risk = risk_engine.calculate_risk(
        detection
    )


    print("\n" + "=" * 60)

    print("THREAT DETECTED")

    print("=" * 60)

    print(
        json.dumps(
            detection,
            indent=2
        )
    )


    print("\nRISK ASSESSMENT")

    print("-" * 60)

    print(
        f"Risk Score : "
        f"{risk['risk_score']}"
    )

    print(
        f"Severity   : "
        f"{risk['severity']}"
    )


    print("Reasons:")

    for reason in risk["reasons"]:

        print(
            f"  + {reason}"
        )


    # ========================================================
    # DASHBOARD — THREAT
    # ========================================================

    write_dashboard_state({

        "status": "THREAT_DETECTED",

        "threat": detection,

        "gnn": gnn_result,

        "context": context,

        "risk": risk,

        "agent": None,

        "safety_gate": None,

        "containment": None,

        "events": get_current_events()

    })


    # ========================================================
    # SECURITY AGENT
    # ========================================================

    agent_result = security_agent.analyze(
        detection,
        risk
    )


    print("\nSECURITY AGENT")

    print("-" * 60)

    print(
        f"Assessment         : "
        f"{agent_result['assessment']}"
    )

    print(
        f"Priority           : "
        f"{agent_result['priority']}"
    )

    print(
        f"Recommended Action : "
        f"{agent_result['recommended_action']}"
    )


    print("Agent Reasoning:")

    for reason in agent_result["reasoning"]:

        print(
            f"  + {reason}"
        )


    # ========================================================
    # DASHBOARD — SECURITY AGENT
    # ========================================================

    write_dashboard_state({

        "status": "ANALYZING_RESPONSE",

        "threat": detection,

        "gnn": gnn_result,

        "context": context,

        "risk": risk,

        "agent": agent_result,

        "safety_gate": None,

        "containment": None,

        "events": get_current_events()

    })


    # ========================================================
    # POLICY SAFETY GATE
    # ========================================================

    policy_result = safety_gate.evaluate(
        agent_result
    )


    print("\nPOLICY SAFETY GATE")

    print("-" * 60)

    print(
        f"Approved : "
        f"{policy_result['approved']}"
    )

    print(
        f"Action   : "
        f"{policy_result['action']}"
    )

    print(
        f"Reason   : "
        f"{policy_result['reason']}"
    )


    # ========================================================
    # DASHBOARD — SAFETY GATE
    # ========================================================

    write_dashboard_state({

        "status": "SAFETY_GATE",

        "threat": detection,

        "gnn": gnn_result,

        "context": context,

        "risk": risk,

        "agent": agent_result,

        "safety_gate": policy_result,

        "containment": None,

        "events": get_current_events()

    })


    # ========================================================
    # CONTAINMENT
    # ========================================================

    containment_result = None


    if (
        policy_result["approved"]
        and
        policy_result["action"] == "ISOLATE_POD"
    ):

        containment_result = (
            containment.isolate_pod(
                detection["namespace"],
                detection["pod"]
            )
        )


        print("\nCONTAINMENT")

        print("-" * 60)

        print(
            f"Success   : "
            f"{containment_result['success']}"
        )

        print(
            f"Action    : "
            f"{containment_result['action']}"
        )

        print(
            f"Namespace : "
            f"{containment_result['namespace']}"
        )

        print(
            f"Pod       : "
            f"{containment_result['pod']}"
        )

        print(
            f"Policy    : "
            f"{containment_result['policy']}"
        )

        print(
            f"Reason    : "
            f"{containment_result['reason']}"
        )


        # ----------------------------------------------------
        # FINAL DASHBOARD STATE
        # ----------------------------------------------------

        final_status = (

            "CONTAINED"

            if containment_result["success"]

            else

            "CONTAINMENT_FAILED"

        )


        write_dashboard_state({

            "status": final_status,

            "threat": detection,

            "gnn": gnn_result,

            "context": context,

            "risk": risk,

            "agent": agent_result,

            "safety_gate": policy_result,

            "containment": containment_result,

            "events": get_current_events()

        })


    else:

        # ----------------------------------------------------
        # No containment
        # ----------------------------------------------------

        write_dashboard_state({

            "status": "DETECTED_NO_CONTAINMENT",

            "threat": detection,

            "gnn": gnn_result,

            "context": context,

            "risk": risk,

            "agent": agent_result,

            "safety_gate": policy_result,

            "containment": None,

            "events": get_current_events()

        })


    print(
        "=" * 60 + "\n"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "[SecMLOps] Starting live detection pipeline..."
    )

    print(
        "[SecMLOps] Waiting for Tetragon events...\n"
    )


    # Initial dashboard state

    write_monitoring_state()


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

            raw_event = json.loads(
                line
            )

            event = normalize_event(
                raw_event
            )

            process_event(
                event
            )


        except json.JSONDecodeError:

            continue


        except Exception as e:

            print(
                f"[ERROR] {e}"
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
