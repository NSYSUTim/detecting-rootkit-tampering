"""Validate recovered signed tokens against the existing endpoint fingerprint.

This is a consistency check, not an exact-set or cryptographic proof. The frozen
fingerprint, IBLT decoder, and historical collectors are deliberately unchanged.
"""
from __future__ import annotations

from typing import Any

from .reconciliation import EntryToken, MASK64, MultisetFingerprint


def _integer(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("out-of-range or non-integer field")
    return value


def _fingerprint(values: Any) -> tuple[int, int, int]:
    if not isinstance(values, (list, tuple)) or len(values) != 3:
        raise ValueError("malformed endpoint fingerprint")
    return tuple(_integer(value, MASK64) for value in values)


def _token(values: Any) -> EntryToken:
    if not isinstance(values, (list, tuple)) or len(values) != 3:
        raise ValueError("malformed recovered token")
    return EntryToken(_integer(values[0], MASK64),
                      _integer(values[1], MASK64), _integer(values[2], 255))


def validate_recovery(kernel_fingerprint: Any, visible_fingerprint: Any,
                      upstream_only: Any, downstream_only: Any,
                      decode_success: Any, residual_cells: Any) -> dict:
    result = {"status": "invalid_data", "verified": False,
              "expected_fingerprint_delta": None,
              "recovered_fingerprint_delta": None, "reasons": []}
    try:
        left, right = _fingerprint(kernel_fingerprint), _fingerprint(visible_fingerprint)
        if type(decode_success) is not bool:
            raise ValueError("decode_success must be boolean")
        if type(residual_cells) is not int or residual_cells < 0:
            raise ValueError("invalid residual count")
        if not isinstance(upstream_only, (list, tuple)) or not isinstance(downstream_only, (list, tuple)):
            raise ValueError("recovered tokens must be sequences")
        recovered = MultisetFingerprint()
        for sign, values in ((1, upstream_only), (-1, downstream_only)):
            for values_for_token in values:
                recovered.add(_token(values_for_token), sign)
        expected = (left[0] - right[0], (left[1] - right[1]) & MASK64,
                    (left[2] - right[2]) & MASK64)
        result["expected_fingerprint_delta"] = list(expected)
        result["recovered_fingerprint_delta"] = list(recovered.as_tuple())
        if not decode_success:
            result.update(status="incomplete", reasons=["decoder_did_not_finish"])
        elif residual_cells != 0:
            result.update(status="invalid_decode_metadata", reasons=["success_with_residual_cells"])
        elif recovered.as_tuple() != expected:
            result.update(status="fingerprint_mismatch", reasons=["recovery_does_not_match_endpoint_delta"])
        else:
            result.update(status="fingerprint_consistent", verified=True)
    except (ValueError, TypeError) as error:
        result["reasons"] = [str(error)]
    return result


def finalize_record(record: dict, program_coverage: dict) -> dict:
    """Produce an explicit verdict without changing the original record.

    The base measurement must already have its return-profile validity gate.
    Program recursion counters add a separate, explicitly limited gate.
    """
    output = dict(record)
    output.update(program_coverage=program_coverage, alarm=None,
                  recovery_verified=False, recovery_status="not_assessed")
    coverage = record.get("coverage")
    valid = (record.get("measurement_valid") is True
             and record.get("verdict") in ("equal", "different")
             and isinstance(coverage, dict) and coverage.get("available") is True
             and coverage.get("valid") is True
             and isinstance(program_coverage, dict)
             and program_coverage.get("available") is True
             and program_coverage.get("valid") is True)
    if not valid:
        output["verdict"] = "invalid"
        output["measurement_valid"] = False
        return output
    visible = record.get("visible_fingerprint")
    if visible is None:
        user = record.get("userspace", {})
        visible = [user.get(field) for field in ("count", "sum1", "sum2")]
    checked = validate_recovery(record.get("kernel_fingerprint"), visible,
                                record.get("upstream_only"), record.get("downstream_only"),
                                record.get("decode_success"), record.get("residual_cells"))
    output["recovery_validation"] = checked
    try:
        equal = _fingerprint(record.get("kernel_fingerprint")) == _fingerprint(visible)
        if record.get("fingerprint_equal") is not equal or record["verdict"] != ("equal" if equal else "different"):
            raise ValueError("inconsistent fingerprint verdict")
    except (ValueError, TypeError):
        output.update(verdict="invalid", measurement_valid=False,
                      recovery_status="invalid_measurement_data")
        return output
    if equal:
        if checked["verified"] and not record["upstream_only"] and not record["downstream_only"]:
            output.update(alarm=False, recovery_status="no_difference_observed")
        else:
            output.update(verdict="invalid", measurement_valid=False,
                          recovery_status="contradictory_summaries")
    else:
        output.update(alarm=True, recovery_verified=checked["verified"],
                      recovery_status="fingerprint_consistent" if checked["verified"] else "unresolved")
    return output
