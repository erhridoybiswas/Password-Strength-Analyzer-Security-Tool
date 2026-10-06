"""
policy_checker.py
-----------------
Policy compliance is SEPARATE from strength scoring.

A password can be STRONG but fail a policy (e.g. it is 10 characters while the
organisation requires 12). A password can be WEAK and pass a weak policy.

Modern guidance (NIST SP 800-63B style):
  * Favour length over forced composition.
  * Do not force arbitrary periodic rotation.
  * Allow spaces and long passwords (128+ chars).
  * Block known-breached / common passwords.
"""

from typing import Dict, List


def check_policy(password: str, is_common: bool, policy: Dict | None = None) -> Dict:
    policy = policy or {}
    min_length = int(policy.get("minimum_length", 12))
    max_length = int(policy.get("maximum_length", 256))
    allow_spaces = bool(policy.get("allow_spaces", True))
    reject_common = bool(policy.get("reject_common_passwords", True))
    require_personal_info_check = bool(policy.get("personal_info_check", True))

    violations: List[str] = []

    if len(password) < min_length:
        violations.append(
            f"Password is shorter than the minimum required length ({min_length})."
        )
    if len(password) > max_length:
        violations.append(
            f"Password exceeds the maximum supported length ({max_length})."
        )
    if not allow_spaces and " " in password:
        violations.append("Spaces are not permitted by this policy.")
    if reject_common and is_common:
        violations.append("Password matches a commonly used password and is rejected.")

    return {
        "policy_pass": len(violations) == 0,
        "violations": violations,
        "policy_used": {
            "minimum_length": min_length,
            "maximum_length": max_length,
            "allow_spaces": allow_spaces,
            "reject_common_passwords": reject_common,
            "personal_info_check": require_personal_info_check,
        },
        "note": (
            "Policy compliance and password strength are different concepts. "
            "A password can pass a policy and still be weak, or fail a policy "
            "while being reasonably strong."
        ),
    }