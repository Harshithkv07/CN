import base64

import pytest

from hrt.config import get_settings
from hrt.guardrail.sandbox import KernelSandbox, build_restore

BASELINE = """*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
"""


def test_build_restore_inserts_before_commit():
    text = build_restore(BASELINE, ["-I INPUT 1 -s 203.0.113.9 -j DROP"])
    lines = text.strip().splitlines()
    assert lines[-1] == "COMMIT"
    assert "-I INPUT 1 -s 203.0.113.9 -j DROP" in text
    assert text.index("-s 203.0.113.9") < text.index("COMMIT")


def test_build_restore_synthesises_filter_if_missing():
    text = build_restore("", ["-A INPUT -s 1.2.3.4 -j DROP"])
    assert text.startswith("*filter") and text.strip().endswith("COMMIT")


@pytest.mark.docker
def test_kernel_verify_accepts_valid_rule():
    s = get_settings()
    sb = KernelSandbox(s)
    if not sb.available():
        pytest.skip("docker/sandbox image not available")
    good = build_restore(BASELINE, ["-I INPUT 1 -s 203.0.113.9 -j DROP"])
    assert sb.verify(good).passed
    bad = build_restore(BASELINE, ["-I INPUT 1 -s 203.0.113.9 --dport 80:70 -p tcp -j DROP"])
    assert not sb.verify(bad).passed
