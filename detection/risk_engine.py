
class RiskEngine:
    def calculate_risk(self, detection):
        score = 0
        reasons = []

        # Evidence-based scoring
        if detection.get("file"):
            score += 20
            reasons.append("Sensitive file access detected")

        if detection.get("destination_ip"):
            score += 20
            reasons.append("Outbound network connection detected")

        if detection.get("attack_type") == "MULTI_STAGE_ACTIVITY":
            score += 20
            reasons.append("Multi-stage activity detected")

        processes = detection.get("processes", [])
        if len(processes) >= 2:
            score += 15
            reasons.append("Multiple processes involved in attack chain")

        if detection.get("time_window_seconds") is not None:
            score += 15
            reasons.append("Events correlated within temporal window")

        # Incorporate GNN output when inference is available.
        gnn = detection.get("gnn", {})
        gnn_available = (
            isinstance(gnn, dict)
            and gnn.get("available") is True
        )

        gnn_probability = None

        if gnn_available:
            try:
                probability = float(
                    gnn.get("suspicious_probability")
                )
                if 0.0 <= probability <= 1.0:
                    gnn_probability = probability
            except (TypeError, ValueError):
                pass

        # GNN contributes up to 20 points, separately from
        # the original evidence score.
        if gnn_probability is not None:
            gnn_points = round(20 * gnn_probability)
            score += gnn_points
            reasons.append(
                f"GNN suspiciousness contributed "
                f"{gnn_points}/20 points"
            )
        else:
            reasons.append(
                "GNN unavailable; using evidence-based score only"
            )

        score = min(score, 100)

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
            "reasons": reasons,
            "gnn_probability": gnn_probability,
        }
