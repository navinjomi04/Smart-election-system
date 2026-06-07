from datetime import datetime

def get_dt(val):
    """Helper to ensure we have a datetime object (handles string or datetime)."""
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(str(val))
    except (ValueError, TypeError):
        return datetime.now()  # Fallback for malformed data