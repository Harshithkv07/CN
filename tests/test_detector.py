import pytest

from hrt.triage.detector import WindowDetector
from hrt.triage.features import sliding_windows, window_features


def _ml_stack_available() -> bool:
    """PyOD/sklearn compiled extensions can be blocked by OS code-integrity policy
    (e.g. Windows Smart App Control on Python 3.14 wheels). Skip rather than fail then."""
    try:
        from pyod.models.iforest import IForest  # noqa: F401
        return True
    except ImportError:
        return False


requires_ml = pytest.mark.skipif(not _ml_stack_available(),
                                 reason="PyOD/scikit-learn DLLs unavailable (blocked by OS application control)")


def _windows(flows):
    return [window_features(fl, 10.0) for _, _, fl in sliding_windows(flows, 10.0, 5.0) if fl]


@requires_ml
def test_iforest_flags_scan_not_benign(benign_flows, scan_flows):
    feats = _windows(benign_flows)
    det = WindowDetector.fit(feats, quantile=0.99)
    # benign windows should almost never be flagged
    flagged = sum(det.detect(f, use_rules=False).ml_anomaly for f in feats)
    assert flagged / len(feats) <= 0.05
    # the scan window should be an anomaly
    scan_feat = window_features(scan_flows, 10.0)
    assert det.detect(scan_feat, use_rules=False).ml_anomaly


def test_needs_minimum_windows():
    with pytest.raises(ValueError):
        WindowDetector.fit([], quantile=0.99)


def test_rules_only_without_model(scan_flows):
    det = WindowDetector()  # no ML
    out = det.detect(window_features(scan_flows, 10.0))
    assert "PORT_SCAN" in out.rules and out.ml_score is None
