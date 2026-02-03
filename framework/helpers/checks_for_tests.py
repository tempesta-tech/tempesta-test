"""Typical checks for functional tests."""

from framework.services.tempesta import Tempesta


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
