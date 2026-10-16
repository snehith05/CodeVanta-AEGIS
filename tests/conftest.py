import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis.engine import Gateway  # noqa: E402
from aegis.models import ToolCall  # noqa: E402
from aegis.policy import Policy  # noqa: E402

POLICY_PATH = ROOT / "policies" / "default.yaml"


@pytest.fixture
def policy() -> Policy:
    return Policy.load(POLICY_PATH)


@pytest.fixture
def gw(policy) -> Gateway:
    return Gateway(policy)


def call(gateway: Gateway, agent: str, tool: str, args: dict, session=None):
    """Evaluate one call (no execution) in an optional session."""
    sid = session.id if session else ""
    return gateway.evaluate(ToolCall(agent, tool, args, sid))


async def submit(gateway: Gateway, agent: str, tool: str, args: dict, session=None, **kw):
    sid = session.id if session else ""
    return await gateway.submit(ToolCall(agent, tool, args, sid), **kw)
