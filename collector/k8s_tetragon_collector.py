#!/usr/bin/env python3

import json
import sys
import uuid

from kafka import KafkaProducer
from kubernetes import client, config, watch


KAFKA_BOOTSTRAP = "kafka.secmlops.svc.cluster.local:9092"
KAFKA_TOPIC = "syscall-events"


def create_kafka_producer():
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda value: json.dumps(
            value, separators=(",", ":")
        ).encode("utf-8"),
        acks="all",
        retries=5,
        linger_ms=10,
    )


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


def normalize_event(raw):
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

    if "process_exec" in raw:
        info = get_process_info(raw["process_exec"])
        result.update(info)
        result["event_type"] = "PROCESS_EXEC"

    elif "process_exit" in raw:
        info = get_process_info(raw["process_exit"])
        result.update(info)
        result["event_type"] = "PROCESS_EXIT"

    elif "process_kprobe" in raw:

        event = raw["process_kprobe"]

        info = get_process_info(event)
        result.update(info)

        function_name = event.get("function_name")
        args = event.get("args", [])

        result["function_name"] = function_name
        result["raw_args"] = args

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

        elif function_name == "tcp_sendmsg":

            result["event_type"] = "NETWORK_SEND"

            if args:
                sock = args[0].get("sock_arg", {})

                result["source_ip"] = sock.get("saddr")
                result["destination_ip"] = sock.get("daddr")
                result["source_port"] = sock.get("sport")
                result["destination_port"] = sock.get("dport")

        elif function_name == "security_file_permission":

            if len(args) >= 2:

                file_info = args[0].get("file_arg", {})
                permission = args[1].get("int_arg")

                result["file_path"] = file_info.get("path")
                result["permission"] = permission

                if permission == 4:
                    result["event_type"] = "FILE_READ"

                elif permission == 2:
                    result["event_type"] = "FILE_WRITE"

                else:
                    result["event_type"] = "FILE_ACCESS"

    return result


def main():

    print("[SecMLOps] Starting Kubernetes Tetragon collector...", flush=True)

    # In-cluster authentication
    config.load_incluster_config()

    core = client.CoreV1Api()

    producer = create_kafka_producer()

    producer.bootstrap_connected()

    print(
        f"[SecMLOps] Kafka connected: {KAFKA_BOOTSTRAP}",
        flush=True
    )

    print(
        f"[SecMLOps] Kafka topic: {KAFKA_TOPIC}",
        flush=True
    )

    # Locate Tetragon pods
    pods = core.list_namespaced_pod(
        namespace="kube-system",
        label_selector="app.kubernetes.io/name=tetragon",
    )

    tetragon_pods = [p.metadata.name for p in pods.items]

    if not tetragon_pods:
        print(
            "[SecMLOps] No Tetragon pods found",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)

    print(
        f"[SecMLOps] Tetragon pods: {tetragon_pods}",
        flush=True,
    )

    w = watch.Watch()

    # Follow Tetragon export stream
    for pod_name in tetragon_pods:

        print(
            f"[SecMLOps] Streaming {pod_name}/export-stdout",
            flush=True,
        )

        try:

            stream = w.stream(
                core.read_namespaced_pod_log,
                name=pod_name,
                namespace="kube-system",
                container="export-stdout",
                follow=True,
                timestamps=False,
            )

            for line in stream:

                line = line.strip()

                if not line:
                    continue

                try:

                    raw_event = json.loads(line)
                    normalized = normalize_event(raw_event)

                    if normalized["event_type"] == "UNKNOWN":
                        continue

                    future = producer.send(
                        KAFKA_TOPIC,
                        normalized
                    )

                    metadata = future.get(timeout=10)

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
                    continue

                except Exception as error:
                    print(
                        f"[Collector] Error: {error}",
                        file=sys.stderr,
                        flush=True,
                    )

        except Exception as error:

            print(
                f"[Tetragon] Stream error: {error}",
                file=sys.stderr,
                flush=True,
            )


if __name__ == "__main__":
    main()

