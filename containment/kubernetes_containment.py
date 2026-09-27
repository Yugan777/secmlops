import subprocess


class KubernetesContainment:

    ALLOWED_NAMESPACE = "security-lab"

    def isolate_pod(self, namespace, pod):

        # Safety check
        if namespace != self.ALLOWED_NAMESPACE:
            return {
                "success": False,
                "action": "ISOLATE_POD",
                "reason": f"Namespace '{namespace}' is not allowed"
            }

        if not pod:
            return {
                "success": False,
                "action": "ISOLATE_POD",
                "reason": "No pod specified"
            }

        policy_name = f"secmlops-isolate-{pod}"

        # NetworkPolicy:
        # - selects only the target pod
        # - allows no ingress
        # - allows no egress
        policy = f"""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {policy_name}
  namespace: {namespace}
spec:
  podSelector:
    matchLabels:
      run: {pod}
  policyTypes:
  - Ingress
  - Egress
"""

        try:
            result = subprocess.run(
                ["kubectl", "apply", "-f", "-"],
                input=policy,
                text=True,
                capture_output=True,
                check=False
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "action": "ISOLATE_POD",
                    "reason": result.stderr.strip()
                }

            return {
                "success": True,
                "action": "ISOLATE_POD",
                "namespace": namespace,
                "pod": pod,
                "policy": policy_name,
                "reason": "NetworkPolicy applied successfully"
            }

        except Exception as exc:
            return {
                "success": False,
                "action": "ISOLATE_POD",
                "reason": str(exc)
            }


if __name__ == "__main__":

    containment = KubernetesContainment()

    result = containment.isolate_pod(
        "security-lab",
        "telemetry-test"
    )

    print("\n========== CONTAINMENT ==========")
    print(f"Success   : {result['success']}")
    print(f"Action    : {result['action']}")
    print(f"Namespace : {result.get('namespace', 'N/A')}")
    print(f"Pod       : {result.get('pod', 'N/A')}")
    print(f"Policy    : {result.get('policy', 'N/A')}")
    print(f"Reason    : {result['reason']}")
    print("=================================")
