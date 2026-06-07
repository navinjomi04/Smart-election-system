from sklearn.ensemble import IsolationForest
import numpy as np

# =========================================================
# TRAINING DATA (NORMAL BEHAVIOR)
# Format:
# [login_attempts, failed_attempts, time_gap, same_ip_count, odd_time]
# =========================================================
X_train = np.array(
    [
        [1, 0, 30, 1, 0],
        [2, 0, 60, 1, 0],
        [1, 1, 20, 1, 0],
        [3, 1, 40, 2, 0],
        [2, 0, 50, 1, 0],
    ]
)

_MODEL_READY = False
model = IsolationForest(contamination=0.2, random_state=42)

try:
    model.fit(X_train)
    _MODEL_READY = True
except Exception:
    _MODEL_READY = False


def _features_from_vote_context(user_id, candidate_id):
    seed = (int(user_id) * 7919 + int(candidate_id) * 9973) % 100000
    return np.array(
        [
            [
                float(1 + (seed % 5)),
                float(seed % 3),
                float(15 + (seed % 75)),
                float(1 + ((seed // 10) % 3)),
                float(1 if ((seed % 24) < 5 or (seed % 24) > 20) else 0),
            ]
        ],
        dtype=float,
    )


import logging

logger = logging.getLogger(__name__)

def check_suspicious(user_id, candidate_id):
    """
    Run isolation forest on features derived from (user_id, candidate_id).
    Returns False (not suspicious) if the model is unavailable or inference fails.
    """
    if not _MODEL_READY:
        return False

    try:
        data = _features_from_vote_context(user_id, candidate_id)
    except Exception:
        return False

    logger.debug(f"ML INPUT: {data}")

    try:
        prediction = model.predict(data)
        score = model.decision_function(data)
        logger.debug(f"ML PREDICTION: {prediction[0]}")
        logger.debug(f"ML SCORE: {score[0]}")
        if prediction[0] == -1:
            logger.info("Suspicious Activity Detected by ML model")
            return True
        return False
    except Exception as exc:
        logger.error(f"ML ERROR: {exc}")
        return False
