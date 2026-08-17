"""Change Intelligence integration boundary and providers."""

from faultwarden.core.config import ChangeSettings, get_settings
from faultwarden.integrations.change.base import ChangeProvider
from faultwarden.integrations.change.composite import CompositeChangeProvider
from faultwarden.integrations.change.deployment import DeploymentChangeProvider
from faultwarden.integrations.change.git import GitChangeProvider


def get_change_provider(settings: ChangeSettings | None = None) -> ChangeProvider:
    """Construct composite change provider using active application settings."""
    cfg = settings or get_settings().change
    providers: list[ChangeProvider] = []

    if cfg.git_repo_path:
        providers.append(GitChangeProvider(repo_path=cfg.git_repo_path))

    if cfg.demo_deployments_url:
        providers.append(DeploymentChangeProvider(endpoint_url=cfg.demo_deployments_url))

    return CompositeChangeProvider(providers)


__all__ = [
    "ChangeProvider",
    "CompositeChangeProvider",
    "DeploymentChangeProvider",
    "GitChangeProvider",
    "get_change_provider",
]
