"""Typical checks for functional tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from framework.services.tempesta import Tempesta

if TYPE_CHECKING:
    from framework.services.tempesta import Stats


def check_tempesta_error_stats(
    tempesta: Tempesta,
    cl_msg_parsing_errors: int,
    srv_msg_parsing_errors: int,
    cl_msg_other_errors: int,
    srv_msg_other_errors: int,
):
    """Check tempesta error stats."""
    tempesta.get_stats()
    msg = "Tempesta has errors in processing HTTP {0}. Received: {1}. Expected: {2}."

    assert tempesta.stats.cl_msg_parsing_errors == cl_msg_parsing_errors, msg.format(
        "requests", tempesta.stats.cl_msg_parsing_errors, cl_msg_parsing_errors
    )
    assert tempesta.stats.srv_msg_parsing_errors == srv_msg_parsing_errors, msg.format(
        "responses", tempesta.stats.srv_msg_parsing_errors, srv_msg_parsing_errors
    )
    assert tempesta.stats.cl_msg_other_errors == cl_msg_other_errors, msg.format(
        "requests", tempesta.stats.cl_msg_other_errors, cl_msg_other_errors
    )
    assert tempesta.stats.srv_msg_other_errors == srv_msg_other_errors, msg.format(
        "responses", tempesta.stats.srv_msg_other_errors, srv_msg_other_errors
    )


def check_tempesta_cache_stats(
    tempesta: Tempesta,
    cache_hits: int,
    cache_misses: int,
    cl_msg_served_from_cache: int,
):
    """Check tempesta cache stats."""
    tempesta.get_stats()
    msg = "Tempesta has caching errors in processing HTTP requests."

    assert tempesta.stats.cache_hits == cache_hits, msg
    assert tempesta.stats.cache_misses == cache_misses, msg
    assert tempesta.stats.cl_msg_served_from_cache == cl_msg_served_from_cache, msg


def check_tempesta_request_and_response_stats(
    tempesta: Tempesta,
    cl_msg_received: int,
    cl_msg_forwarded: int,
    srv_msg_received: int,
    srv_msg_forwarded: int,
):
    """Check tempesta request and response stats."""
    tempesta.get_stats()
    msg = "Tempesta has errors in processing HTTP {0}. Received: {1}. Expected: {2}."

    assert tempesta.stats.cl_msg_received == cl_msg_received, msg.format(
        "requests", tempesta.stats.cl_msg_received, cl_msg_received
    )
    assert tempesta.stats.cl_msg_forwarded == cl_msg_forwarded, msg.format(
        "requests", tempesta.stats.cl_msg_forwarded, cl_msg_forwarded
    )
    assert tempesta.stats.srv_msg_received == srv_msg_received, msg.format(
        "responses", tempesta.stats.srv_msg_received, srv_msg_received
    )
    assert tempesta.stats.srv_msg_forwarded == srv_msg_forwarded, msg.format(
        "responses", tempesta.stats.srv_msg_forwarded, srv_msg_forwarded
    )


@dataclass(frozen=True)
class CdnAmplificationBypassSignal:
    """
    Heuristic signal from ``/proc/tempesta/perfstat`` for CDN amplification
    and cache-bypass traffic (escudo#441 filtration).

    Attackers often avoid error floods and instead force origin traffic with
    unique URI query parameters and/or ``Cache-Control: no-cache``, producing:
    - high cache miss rate and origin forwards;
    - very low client parse / other error rates;
    - mostly successful responses (checked separately via health_statuses).
    """

    miss_ratio: float
    origin_forward_ratio: float
    error_ratio: float
    cache_hits: int
    cache_misses: int
    cl_msg_received: int
    cl_msg_forwarded: int
    cl_msg_served_from_cache: int
    cl_msg_parsing_errors: int
    cl_msg_other_errors: int
    detected: bool


def analyze_cdn_amplification_bypass(
    stats: Stats,
    *,
    min_requests: int = 10,
    min_miss_ratio: float = 0.8,
    min_origin_forward_ratio: float = 0.8,
    max_error_ratio: float = 0.05,
) -> CdnAmplificationBypassSignal:
    """
    Classify perfstat snapshot for cache-bypass / origin-amplification patterns.

    Filtration logic intended for Escudo CDN amplification & bypass detection
    (escudo#441): flag traffic that stresses cache/origin with valid requests
    rather than generating many error responses.
    """
    received = max(stats.cl_msg_received, 0)
    hits = max(stats.cache_hits, 0)
    misses = max(stats.cache_misses, 0)
    forwarded = max(stats.cl_msg_forwarded, 0)
    served_cache = max(stats.cl_msg_served_from_cache, 0)
    parse_err = max(stats.cl_msg_parsing_errors, 0)
    other_err = max(stats.cl_msg_other_errors, 0)

    cache_lookups = hits + misses
    miss_ratio = (misses / cache_lookups) if cache_lookups else 0.0
    origin_forward_ratio = (forwarded / received) if received else 0.0
    error_ratio = ((parse_err + other_err) / received) if received else 0.0

    detected = (
        received >= min_requests
        and miss_ratio >= min_miss_ratio
        and origin_forward_ratio >= min_origin_forward_ratio
        and error_ratio <= max_error_ratio
    )

    return CdnAmplificationBypassSignal(
        miss_ratio=miss_ratio,
        origin_forward_ratio=origin_forward_ratio,
        error_ratio=error_ratio,
        cache_hits=hits,
        cache_misses=misses,
        cl_msg_received=received,
        cl_msg_forwarded=forwarded,
        cl_msg_served_from_cache=served_cache,
        cl_msg_parsing_errors=parse_err,
        cl_msg_other_errors=other_err,
        detected=detected,
    )


def assert_cdn_amplification_bypass_detected(
    tempesta: Tempesta,
    *,
    min_requests: int = 10,
    min_miss_ratio: float = 0.8,
    min_origin_forward_ratio: float = 0.8,
    max_error_ratio: float = 0.05,
) -> CdnAmplificationBypassSignal:
    """Load perfstat and assert amplification/bypass filtration signal is raised."""
    tempesta.get_stats()
    signal = analyze_cdn_amplification_bypass(
        tempesta.stats,
        min_requests=min_requests,
        min_miss_ratio=min_miss_ratio,
        min_origin_forward_ratio=min_origin_forward_ratio,
        max_error_ratio=max_error_ratio,
    )
    assert signal.detected, (
        "Expected CDN amplification / cache-bypass pattern in perfstat "
        f"(escudo#441 filtration), got: {signal}"
    )
    return signal
