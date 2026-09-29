import json
import os
from datetime import datetime

from neo4j import GraphDatabase
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, to_timestamp
from pyspark.sql.types import (
    StructType,
    StructField,
    StringType,
    LongType,
    ArrayType,
    MapType,
)


# ============================================================
# CONFIG
# ============================================================

KAFKA_BOOTSTRAP = "127.0.0.1:9092"
KAFKA_TOPIC = "syscall-events"

NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD")

if not NEO4J_PASSWORD:
    raise RuntimeError(
        "NEO4J_PASSWORD environment variable is not set."
    )


# ============================================================
# SPARK
# ============================================================

spark = (
    SparkSession.builder
    .appName("SecMLOps-Kafka-To-Neo4j")
    .master("local[2]")
    .config("spark.driver.memory", "1g")
    .config("spark.executor.memory", "1g")
    .config("spark.sql.shuffle.partitions", "2")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")


# ============================================================
# KAFKA EVENT SCHEMA
# ============================================================

schema = StructType([
    StructField("event_id", StringType(), True),
    StructField("timestamp", StringType(), True),
    StructField("event_type", StringType(), True),

    StructField("process", StringType(), True),
    StructField("pid", LongType(), True),
    StructField("exec_id", StringType(), True),
    StructField("parent_exec_id", StringType(), True),
    StructField("arguments", StringType(), True),

    StructField("pod", StringType(), True),
    StructField("namespace", StringType(), True),
    StructField("container", StringType(), True),
    StructField("workload", StringType(), True),
    StructField("uid", LongType(), True),
    StructField("function_name", StringType(), True),

    StructField(
        "raw_args",
        ArrayType(MapType(StringType(), StringType())),
        True
    ),

    StructField("source_ip", StringType(), True),
    StructField("destination_ip", StringType(), True),
    StructField("source_port", LongType(), True),
    StructField("destination_port", LongType(), True),
])


# ============================================================
# READ KAFKA
# ============================================================

raw = (
    spark.readStream
    .format("kafka")
    .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
    .option("subscribe", KAFKA_TOPIC)
    .option("startingOffsets", "latest")
    .option("failOnDataLoss", "false")
    .load()
)


events = (
    raw
    .selectExpr("CAST(value AS STRING) AS json")
    .select(from_json(col("json"), schema).alias("e"))
    .select("e.*")
)


# ============================================================
# SECURITY FILTERING
# ============================================================

security_event_types = [
    "PROCESS_EXEC",
    "PROCESS_EXIT",
    "FILE_READ",
    "FILE_WRITE",
    "NETWORK_CONNECT",
]

filtered = (
    events
    .filter(col("event_type").isin(security_event_types))
    .filter(
        ~(
            (col("namespace") == "secmlops")
            &
            (
                col("workload").isin(
                    "kafka-controller",
                    "secmlops-collector"
                )
            )
        )
    )
)


# ============================================================
# NEO4J WRITER
# ============================================================

def write_batch(batch_df, batch_id):

    rows = batch_df.collect()

    if not rows:
        print(f"[Spark] Batch {batch_id}: no security events")
        return

    print(
        f"[Spark] Batch {batch_id}: "
        f"processing {len(rows)} security events"
    )

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASSWORD)
    )

    def write_event(tx, event):

        event_id = event["event_id"]
        timestamp = event["timestamp"]
        event_type = event["event_type"]

        process = event["process"]
        exec_id = event["exec_id"]
        parent_exec_id = event["parent_exec_id"]

        pod = event["pod"]
        namespace = event["namespace"]
        container = event["container"]
        workload = event["workload"]

        destination_ip = event["destination_ip"]
        destination_port = event["destination_port"]

        tx.run(
            """
            MERGE (e:Event {event_id: $event_id})

            SET
                e.timestamp = datetime($timestamp),
                e.event_type = $event_type,
                e.process = $process,
                e.exec_id = $exec_id,
                e.parent_exec_id = $parent_exec_id,
                e.destination_ip = $destination_ip,
                e.destination_port = $destination_port

            MERGE (w:Workload {
                namespace: $namespace,
                name: $workload
            })

            MERGE (p:Process {
                exec_id: $exec_id
            })

            SET
                p.path = $process,
                p.pod = $pod,
                p.container = $container

            MERGE (e)-[:OBSERVED_IN]->(w)
            MERGE (e)-[:INVOLVES]->(p)
            """,
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            process=process,
            exec_id=exec_id,
            parent_exec_id=parent_exec_id,
            destination_ip=destination_ip,
            destination_port=destination_port,
            namespace=namespace,
            workload=workload,
            pod=pod,
            container=container,
        )

        # ----------------------------------------------------
        # FILE EVENT
        # ----------------------------------------------------

        if event_type in ("FILE_READ", "FILE_WRITE"):

            # The collector places the path in arguments.
            file_path = event["arguments"]

            if file_path:
                tx.run(
                    """
                    MATCH (e:Event {event_id: $event_id})
                    MATCH (p:Process {exec_id: $exec_id})

                    MERGE (f:File {path: $file_path})

                    MERGE (p)-[r:FILE_ACTIVITY {
                        event_id: $event_id
                    }]->(f)

                    SET
                        r.operation = $operation,
                        r.timestamp = datetime($timestamp)

                    MERGE (e)-[:TARGETS]->(f)
                    """,
                    event_id=event_id,
                    exec_id=exec_id,
                    file_path=file_path,
                    operation=event_type,
                    timestamp=timestamp,
                )

        # ----------------------------------------------------
        # NETWORK EVENT
        # ----------------------------------------------------

        if event_type == "NETWORK_CONNECT":

            if destination_ip:

                tx.run(
                    """
                    MATCH (e:Event {event_id: $event_id})
                    MATCH (p:Process {exec_id: $exec_id})

                    MERGE (n:NetworkEndpoint {
                        ip: $destination_ip,
                        port: $destination_port
                    })

                    MERGE (p)-[r:CONNECTS_TO {
                        event_id: $event_id
                    }]->(n)

                    SET
                        r.timestamp = datetime($timestamp)

                    MERGE (e)-[:TARGETS]->(n)
                    """,
                    event_id=event_id,
                    exec_id=exec_id,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    timestamp=timestamp,
                )

    try:

        with driver.session(database="neo4j") as session:

            for row in rows:
                event = row.asDict(recursive=True)

                try:
                    session.execute_write(
                        write_event,
                        event
                    )

                except Exception as exc:
                    print(
                        f"[Neo4j] Failed event "
                        f"{event.get('event_id')}: {exc}"
                    )

    finally:
        driver.close()

    print(
        f"[Spark] Batch {batch_id}: "
        f"Neo4j write complete"
    )


# ============================================================
# START STREAM
# ============================================================

query = (
    filtered
    .writeStream
    .foreachBatch(write_batch)
    .outputMode("update")
    .option(
        "checkpointLocation",
        os.path.expanduser(
            "~/secmlops/logs/spark-checkpoint"
        )
    )
    .trigger(processingTime="5 seconds")
    .start()
)


print("[Spark] SecMLOps Kafka → Neo4j pipeline started.")

query.awaitTermination()
