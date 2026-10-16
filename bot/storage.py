"""Persistent state for the bot, stored as files inside a GitHub repo.

The bot runs inside GitHub Actions whose file system is discarded after every
run, so the repo *is* the database:

    data/state.json      -> users, their configs, server inventory
    subs/<token>.txt     -> base64 subscription (stable URL, content updated in place)
    configs/<token>.json -> full client JSON

Writes go through the GitHub Contents API with the file SHA, so two overlapping
runs cannot silently overwrite each other (conflict -> re-read -> retry).
Unchanged content is never committed (prevents Actions trigger loops).
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from typing import Any

from github import Github, GithubException, InputGitAuthor

AUTHOR = InputGitAuthor("killdpi-bot", "killdpi-bot@users.noreply.github.com")


class Storage:
    def __init__(self, token: str, repo_full_name: str, branch: str = "main"):
        self.gh = Github(token, per_page=100)
        self.repo = self.gh.get_repo(repo_full_name)
        self.branch = branch
        self._cache: dict[str, tuple[str, str]] = {}

    def read(self, path: str, default: str | None = None) -> str | None:
        try:
            f = self.repo.get_contents(path, ref=self.branch)
            content = base64.b64decode(f.content).decode()
            self._cache[path] = (f.sha, content)
            return content
        except GithubException as e:
            if e.status == 404:
                self._cache.pop(path, None)
                return default
            raise

    def write(self, path: str, content: str, message: str, retries: int = 3) -> None:
        for attempt in range(retries):
            try:
                if path not in self._cache:
                    self.read(path)
                cached = self._cache.get(path)
                if cached and cached[1] == content:
                    return
                if cached:
                    r = self.repo.update_file(path, message, content, cached[0], branch=self.branch, author=AUTHOR, committer=AUTHOR)
                else:
                    r = self.repo.create_file(path, message, content, branch=self.branch, author=AUTHOR, committer=AUTHOR)
                self._cache[path] = (r["content"].sha, content)
                return
            except GithubException as e:
                if e.status in (409, 422) and attempt < retries - 1:
                    self._cache.pop(path, None)
                    time.sleep(1 + attempt)
                    continue
                raise

    def load_state(self) -> dict[str, Any]:
        raw = self.read("data/state.json")
        if not raw:
            return {"version": 1, "users": {}, "servers": [], "configs": {}}
        return json.loads(raw)

    def save_state(self, state: dict[str, Any], message: str = "bot: update state") -> None:
        self.write("data/state.json", json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True) + "\n", message)

    def publish_subscription(self, token: str, links: list[str], message: str) -> str:
        body = base64.b64encode("\n".join(links).encode()).decode()
        self.write(f"subs/{token}.txt", body + "\n", message)
        return self.raw_url(f"subs/{token}.txt")

    def publish_config(self, token: str, client_json: str, message: str) -> str:
        self.write(f"configs/{token}.json", client_json.rstrip("\n") + "\n", message)
        return self.raw_url(f"configs/{token}.json")

    def raw_url(self, path: str) -> str:
        return f"https://raw.githubusercontent.com/{self.repo.full_name}/{self.branch}/{path}"

    @staticmethod
    def new_token() -> str:
        return secrets.token_urlsafe(12)


class LocalStorage(Storage):
    """Drop-in replacement for local development / tests (no GitHub)."""

    def __init__(self, root: str = "data_local"):
        self.root = root
        self.branch = "local"
        self._cache = {}
        os.makedirs(root, exist_ok=True)

    def read(self, path: str, default: str | None = None) -> str | None:
        p = os.path.join(self.root, path)
        return open(p, encoding="utf-8").read() if os.path.exists(p) else default

    def write(self, path: str, content: str, message: str, retries: int = 3) -> None:
        p = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write(content)

    def raw_url(self, path: str) -> str:
        return f"file://{os.path.abspath(os.path.join(self.root, path))}"
