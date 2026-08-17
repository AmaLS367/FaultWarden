"""Bounded read-only Git change provider inspecting local repository history."""

import asyncio
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from faultwarden.core.logging import get_logger
from faultwarden.schemas.change import (
    ChangeType,
    ConfigurationChange,
    OperationalChange,
)

logger = get_logger("faultwarden.integrations.change.git")

# Bounded caps to prevent token exhaustion and slow queries
MAX_COMMITS_DEFAULT: int = 20
MAX_FILES_PER_COMMIT: int = 15
MAX_DIFF_CHARS: int = 1500
SUBPROCESS_TIMEOUT_SECONDS: float = 5.0

# Regex for common config key assignments in commit messages or diffs: KEY=value or KEY: old -> new
_CONFIG_DIFF_REGEX: re.Pattern[str] = re.compile(
    r"^\s*([A-Z0-9_]{3,40})\s*(?::\s*(\S+)\s*(?:->|=>|to)\s*(\S+)|\s*=\s*(\S+))\s*$",
    re.MULTILINE,
)


# --- Git Provider Implementation ---
class GitChangeProvider:
    """Read-only provider that extracts bounded commit history from a local Git repository."""

    def __init__(
        self,
        repo_path: str = ".",
        timeout_seconds: float = SUBPROCESS_TIMEOUT_SECONDS,
    ) -> None:
        self.repo_path = str(Path(repo_path).resolve())
        self.timeout_seconds = timeout_seconds

    def _is_git_repo(self) -> bool:
        """Check whether the configured repository path contains a valid .git directory or parent."""
        base = Path(self.repo_path)
        return (base / ".git").exists() or (base.parent / ".git").exists()

    async def _run_git_command(self, args: list[str]) -> str | None:
        """Run a fixed read-only Git subprocess with strict timeouts and return stdout."""
        try:
            process = await asyncio.create_subprocess_exec(
                "git",
                *args,
                cwd=self.repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )
            if process.returncode != 0:
                logger.warning(
                    "git_command_non_zero_exit",
                    args=args,
                    returncode=process.returncode,
                    stderr=stderr.decode("utf-8", errors="replace")[:200],
                )
                return None
            return stdout.decode("utf-8", errors="replace")
        except TimeoutError:
            logger.warning("git_command_timed_out", args=args, timeout=self.timeout_seconds)
            return None
        except FileNotFoundError:
            logger.warning("git_executable_not_found")
            return None
        except Exception as exc:
            logger.warning("git_command_execution_failed", args=args, error=str(exc))
            return None

    def _extract_config_changes(self, text: str) -> list[ConfigurationChange]:
        """Extract structured configuration parameter changes from commit text or diff snippets."""
        changes: list[ConfigurationChange] = []
        for match in _CONFIG_DIFF_REGEX.finditer(text):
            key = match.group(1)
            if match.group(2) and match.group(3):
                old_val = match.group(2)
                new_val = match.group(3)
            elif match.group(4):
                old_val = None
                new_val = match.group(4)
            else:
                continue
            changes.append(
                ConfigurationChange(
                    key=key,
                    old_value=old_val,
                    new_value=new_val,
                    scope="service",
                )
            )
        return changes

    async def list_changes(
        self,
        service: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = MAX_COMMITS_DEFAULT,
    ) -> list[OperationalChange]:
        """Query bounded Git commits within the specified time window."""
        if not self._is_git_repo():
            logger.info("git_repo_not_found_skipping_git_provider", path=self.repo_path)
            return []

        # Format ISO strings for git log --since / --until
        since_iso = start_time.isoformat()
        until_iso = end_time.isoformat()
        bounded_limit = min(limit, MAX_COMMITS_DEFAULT)

        # Record separator: %x1e (Record Separator ASCII 30), Field separator: %x00 (NUL)
        # Format: SHA %x00 Author %x00 AuthorDateISO %x00 Subject %x00 Body %x1e
        log_args = [
            "log",
            f"--since={since_iso}",
            f"--until={until_iso}",
            f"-n{bounded_limit}",
            "--pretty=format:%H%x00%an%x00%aI%x00%s%x00%b%x1e",
        ]

        raw_log = await self._run_git_command(log_args)
        if not raw_log:
            return []

        records = [rec for rec in raw_log.split("\x1e") if rec.strip()]
        changes: list[OperationalChange] = []

        for rec in records:
            fields = rec.split("\x00")
            if len(fields) < 4:
                continue
            commit_sha = fields[0].strip()
            author = fields[1].strip()
            date_str = fields[2].strip()
            subject = fields[3].strip()
            body = fields[4].strip() if len(fields) > 4 else ""

            try:
                commit_ts = datetime.fromisoformat(date_str)
            except Exception:
                continue

            # Fetch modified files for this commit (bounded)
            files_args = ["diff-tree", "--no-commit-id", "--name-only", "-r", commit_sha]
            raw_files = await self._run_git_command(files_args)
            files_changed = (
                [f.strip() for f in raw_files.splitlines() if f.strip()][:MAX_FILES_PER_COMMIT]
                if raw_files
                else []
            )

            # Extract possible config changes from message and body
            combined_text = f"{subject}\n{body}"
            config_changes = self._extract_config_changes(combined_text)

            # If commit SHA is a valid 40-char hex string, fetch bounded diff to extract real config changes
            diff_snippet: str | None = None
            if re.match(r"^[0-9a-fA-F]{40}$", commit_sha):
                diff_args = ["show", "--format=", "--unified=1", "--no-ext-diff", commit_sha]
                raw_diff = await self._run_git_command(diff_args)
                if raw_diff:
                    diff_snippet = raw_diff[:MAX_DIFF_CHARS]
                    diff_configs = self._extract_config_changes(diff_snippet)
                    existing_keys = {c.key.upper() for c in config_changes}
                    for dc in diff_configs:
                        if dc.key.upper() not in existing_keys:
                            config_changes.append(dc)
                            existing_keys.add(dc.key.upper())

            # Bounded description
            description = body[:MAX_DIFF_CHARS] if body else None

            meta: dict[str, Any] = {"commit_sha_full": commit_sha}
            if diff_snippet:
                meta["diff_preview"] = diff_snippet[:300]

            change = OperationalChange(
                id=f"git-{commit_sha[:10]}",
                source="git",
                change_type=ChangeType.GIT_COMMIT,
                service=service,
                timestamp=commit_ts,
                actor=author,
                version=commit_sha[:7],
                commit_sha=commit_sha,
                deployment_id=None,
                title=subject,
                description=description,
                metadata=meta,
                files_changed=files_changed,
                config_changes=config_changes,
                previous_version=None,
                new_version=commit_sha[:7],
            )
            changes.append(change)

        logger.info(
            "git_changes_retrieved",
            service=service,
            count=len(changes),
            start_time=since_iso,
            end_time=until_iso,
        )
        return changes
