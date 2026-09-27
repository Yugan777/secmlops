#!/usr/bin/env python3

import json
import subprocess
import sys
import uuid
from datetime import datetime

from kafka import KafkaProducer


# =========================================================
# KAFKA CONFIGURATION
# =========================================================

KAFKA_BOOTSTRAP = "kafka.secmlops.svc.cluster.local:9092"
KAFKA_TOPIC = "syscall-events"


def create_kafka_producer():
    """
    Create Kafka producer for normalized SecMLOps events.
    """

    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda value: json.dumps(
            value,
            separators=(",", ":")
        ).encode("utf-8"),
        acks="all",
        retries=5,
        linger_ms=10,
    )


# =========================================================
# PROCESS INFORMATION
# =========================================================

def get_process_info(event):

    process = event.get("process", {})
    pod = process.get("pod", {})

    return {
        "exec_id": process.get("exec_id"),
        "pid": process.get("pid"),
        "uid": process.get("uid"),
        "process": process.get("binary"),
        "arguments": process.get("arguments"),
        "parent_exec_id": process.get("parent_exec_id"),
        "pod": pod.get("name"),
        "namespace": pod.get("namespace"),
        "container": pod.get("container", {}).get("name"),
        "workload": pod.get("workload"),
    }


# =========================================================
# EVENT NORMALIZATION
# =========================================================

def normalize_event(raw):
    """
    Convert one Tetragon JSON event into a SecMLOps event.
    """

    result = {
        "event_id": str(uuid.uuid4()),
        "timestamp": raw.get("time"),
        "event_type": "UNKNOWN",

        "process": None,
        "pid": None,
        "exec_id": None,
        "parent_exec_id": None,
        "arguments": None,

        "pod": None,
        "namespace": None,
        "container": None,
        "workload": None,
    }

    # ---------------------------------------------------------
    # PROCESS EXECUTION
    # ---------------------------------------------------------

    if "process_exec" in raw:

        event = raw["process_exec"]
        info = get_process_info(event)

        result.update(info)
        result["event_type"] = "PROCESS_EXEC"

    # ---------------------------------------------------------
    # PROCESS EXIT
    # ---------------------------------------------------------

    elif "process_exit" in raw:

        event = raw["process_exit"]
        info = get_process_info(event)

        result.update(info)
        result["event_type"] = "PROCESS_EXIT"

    # ---------------------------------------------------------
    # KERNEL PROBE EVENTS
    # ---------------------------------------------------------

    elif "process_kprobe" in raw:

        event = raw["process_kprobe"]

        info = get_process_info(event)
        result.update(info)

        function_name = event.get("function_name")
        args = event.get("args", [])

        result["function_name"] = function_name
        result["raw_args"] = args

        # -----------------------------------------------------
        # NETWORK CONNECTION
        # -----------------------------------------------------

        if function_name == "tcp_connect":

            result["event_type"] = "NETWORK_CONNECT"

            if args:

                sock = args[0].get("sock_arg", {})

                result["source_ip"] = sock.get("saddr")
                result["destination_ip"] = sock.get("daddr")
                result["source_port"] = sock.get("sport")
                result["destination_port"] = sock.get("dport")
                result["protocol"] = sock.get("protocol")
                result["connection_state"] = sock.get("state")

        # -----------------------------------------------------
        # NETWORK SEND
        # -----------------------------------------------------

        elif function_name == "tcp_sendmsg":

            result["event_type"] = "NETWORK_SEND"

            if args:

                sock = args[0].get("sock_arg", {})

                result["source_ip"] = sock.get("saddr")
                result["destination_ip"] = sock.get("daddr")
                result["source_port"] = sock.get("sport")
                result["destination_port"] = sock.get("dport")

        # -----------------------------------------------------
        # FILE ACCESS
        # -----------------------------------------------------

        elif function_name == "security_file_permission":

            if len(args) >= 2:

                file_info = args[0].get("file_arg", {})
                permission = args[1].get("int_arg")

                result["file_path"] = file_info.get("path")
                result["permission"] = permission

                # Linux MAY_READ = 4
                if permission == 4:
                    result["event_type"] = "FILE_READ"

                # Linux MAY_WRITE = 2
                elif permission == 2:
                    result["event_type"] = "FILE_WRITE"

                else:
                    result["event_type"] = "FILE_ACCESS"

    return result


# =========================================================
# TETRAGON STREAM
# =========================================================

def stream_tetragon():

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

    print("[SecMLOps] Starting Tetragon collector...", flush=True)

    # ---------------------------------------------------------
    # Kafka connection
    # ---------------------------------------------------------

    try:

        producer = create_kafka_producer()

        # Force initial connection
        producer.bootstrap_connected()

        print(
            f"[SecMLOps] Kafka connected: "
            f"{KAFKA_BOOTSTRAP}",
            flush=True
        )

        print(
            f"[SecMLOps] Kafka topic: "
            f"{KAFKA_TOPIC}",
            flush=True
        )

    except Exception as error:

        print(
            f"[Kafka] Connection failed: {error}",
            file=sys.stderr,
            flush=True,
        )

        sys.exit(1)

    # ---------------------------------------------------------
    # Start Tetragon
    # ---------------------------------------------------------

    print(
        "[SecMLOps] Waiting for Tetragon events...",
        flush=True
    )

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # ---------------------------------------------------------
    # Process events
    # ---------------------------------------------------------

    for line in process.stdout:

        line = line.strip()

        if not line:
            continue

        try:

            raw_event = json.loads(line)

            normalized = normalize_event(raw_event)

            if normalized["event_type"] == "UNKNOWN":
                continue

            # -------------------------------------------------
            # Publish to Kafka
            # -------------------------------------------------

            future = producer.send(
                KAFKA_TOPIC,
                normalized
            )

            # Wait for broker acknowledgement
            metadata = future.get(timeout=10)

            # -------------------------------------------------
            # Local output
            # -------------------------------------------------

            print(
                json.dumps(
                    normalized,
                    separators=(",", ":")
                ),
                flush=True,
            )

            print(
                f"[Kafka] Published "
                f"{normalized['event_type']} "
                f"partition={metadata.partition} "
                f"offset={metadata.offset}",
                flush=True,
            )

        except json.JSONDecodeError:

            print(
                "[Collector] Ignoring non-JSON line",
                file=sys.stderr,
                flush=True,
            )

        except Exception as error:

            print(
                f"[Collector] Error: {error}",
                file=sys.stderr,
                flush=True,
            )

    producer.flush()


if __name__ == "__main__":

    stream_tetragon()
