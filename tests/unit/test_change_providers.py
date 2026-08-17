"""Unit tests for change providers (GitChangeProvider, DeploymentChangeProvider, CompositeChangeProvider)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from faultwarden.integrations.change.base import ChangeProvider
from faultwarden.integrations.change.composite import CompositeChangeProvider
from faultwarden.integrations.change.deployment import DeploymentChangeProvider
from faultwarden.integrations.change.git import GitChangeProvider
from faultwarden.schemas.change import ChangeType, OperationalChange


@pytest.mark.asyncio
async def test_git_change_provider_parsing() -> None:
    """Test GitChangeProvider parsing simulated git log output."""
    provider = GitChangeProvider(repo_path=".")

    simulated_log = "a81cf2e9401d\x00sre-bob\x002026-08-17T05:00:00+00:00\x00Reduce pool size to 5 for testing\x00DB_POOL_SIZE: 20 -> 5\x1e"
    simulated_diff = "demo_service/app/main.py\nconfigs/prod.env\n"

    with (
        patch.object(provider, "_is_git_repo", return_value=True),
        patch.object(provider, "_run_git_command", new_callable=AsyncMock) as mock_git,
    ):
        mock_git.side_effect = [simulated_log, simulated_diff]

        start_time = datetime(2026, 8, 17, 4, 0, 0, tzinfo=UTC)
        end_time = datetime(2026, 8, 17, 6, 0, 0, tzinfo=UTC)

        changes = await provider.list_changes("demo-service", start_time, end_time)

        assert len(changes) == 1
        ch = changes[0]
        assert ch.id == "git-a81cf2e940"
        assert ch.service == "demo-service"
        assert ch.change_type == ChangeType.GIT_COMMIT
        assert "Reduce pool size" in ch.title
        assert len(ch.files_changed) == 2
        assert len(ch.config_changes) >= 1
        assert any(c.key == "DB_POOL_SIZE" for c in ch.config_changes)


@pytest.mark.asyncio
async def test_git_change_provider_not_repo_graceful_fallback() -> None:
    """Test that GitChangeProvider gracefully returns empty list if directory is not a git repo."""
    provider = GitChangeProvider(repo_path="/nonexistent/directory")
    with patch.object(provider, "_is_git_repo", return_value=False):
        now = datetime.now(UTC)
        changes = await provider.list_changes("demo-service", now, now)
        assert changes == []


@pytest.mark.asyncio
async def test_deployment_change_provider_http() -> None:
    """Test DeploymentChangeProvider querying HTTP endpoint with mocked response."""
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    mock_payload = [
        {
            "id": "deploy-002",
            "service": "demo-service",
            "version": "1.0.1",
            "environment": "production",
            "commit_sha": "a81cf2e9401d",
            "deployed_by": "sre-deployer",
            "status": "SUCCESS",
            "timestamp": now_iso,
            "config_changes": [
                {
                    "key": "DB_POOL_SIZE",
                    "old_value": "20",
                    "new_value": "5",
                    "component": "database",
                }
            ],
        }
    ]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(mock_handler)
    provider = DeploymentChangeProvider(
        endpoint_url="http://demo-service:8000/deployments",
        transport=transport,
    )

    start_time = datetime.now(UTC) - timedelta(hours=1)
    end_time = datetime.now(UTC) + timedelta(hours=1)

    changes = await provider.list_changes("demo-service", start_time, end_time)

    assert len(changes) == 1
    assert changes[0].id == "deploy-deploy-002"
    assert changes[0].service == "demo-service"
    assert changes[0].change_type == ChangeType.DEPLOYMENT
    assert len(changes[0].config_changes) == 1
    assert changes[0].config_changes[0].key == "DB_POOL_SIZE"


@pytest.mark.asyncio
async def test_composite_change_provider() -> None:
    """Test CompositeChangeProvider aggregating and deduplicating changes chronologically."""
    t1 = datetime(2026, 8, 17, 4, 30, 0, tzinfo=UTC)
    t2 = datetime(2026, 8, 17, 5, 0, 0, tzinfo=UTC)

    ch1 = OperationalChange(
        id="git-1",
        source="git",
        service="demo-service",
        change_type=ChangeType.GIT_COMMIT,
        title="Commit 1",
        timestamp=t1,
    )
    ch2 = OperationalChange(
        id="deploy-1",
        source="deployment",
        service="demo-service",
        change_type=ChangeType.DEPLOYMENT,
        title="Deploy 1",
        timestamp=t2,
    )

    class MockP1(ChangeProvider):
        async def list_changes(
            self,
            service: str,
            start_time: datetime,
            end_time: datetime,
            limit: int = 50,
        ) -> list[OperationalChange]:
            return [ch1]

    class MockP2(ChangeProvider):
        async def list_changes(
            self,
            service: str,
            start_time: datetime,
            end_time: datetime,
            limit: int = 50,
        ) -> list[OperationalChange]:
            return [ch2]

    composite = CompositeChangeProvider([MockP1(), MockP2()])
    changes = await composite.list_changes("demo-service", t1, t2)

    assert len(changes) == 2
    # Should be sorted chronologically descending (newest first)
    assert changes[0].id == "deploy-1"
    assert changes[1].id == "git-1"
