"""
Quantum timeline configuration for PQMail.

The timeline represents the estimated number of years until a
cryptographically relevant quantum computer becomes available.
"""

VALID_TIMELINES = [5, 10, 15]

DEFAULT_TIMELINE = 10


def validate_timeline(timeline: int) -> int:
    """
    Validate the quantum timeline scenario.

    Allowed values:
    - 5 years: aggressive timeline
    - 10 years: moderate timeline
    - 15 years: conservative timeline
    """
    if timeline not in VALID_TIMELINES:
        raise ValueError(
            f"Invalid quantum timeline: {timeline}. "
            f"Allowed values are {VALID_TIMELINES}."
        )

    return timeline