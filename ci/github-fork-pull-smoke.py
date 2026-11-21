#!/usr/bin/env python3
"""Protected CI smoke for GitHub fork pull creation through the MCP shim."""

import argparse
import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


PREFIX = "agent/github-fork-smoke/"
API = "https://api.github.com"
ALIAS = "github-smoke"
TIMEOUT = 30


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def setting(name):
    value = os.environ.get(f"GITHUB_FORK_SMOKE_{name}", "")
    require(value and value == value.strip(), f"Missing or invalid smoke setting {name}")
    return value


def repo_setting(name):
    value = setting(name)
    require(
        re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", value)
        and value.split("/")[1] not in {".", ".."},
        f"Invalid owner/repository in smoke setting {name}",
    )
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class GitHub:
    def __init__(self, token):
        self.token = token
        self.http = build_opener(NoRedirect())

    def call(self, method, path, data=None, status=200):
        request = Request(
            API + path,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": "forge-mcp-github-fork-smoke",
            },
            method=method,
            data=json.dumps(data).encode() if data is not None else None,
        )
        try:
            with self.http.open(request, timeout=TIMEOUT) as reply:
                require(reply.status == status, f"GitHub {method} {path}: HTTP {reply.status}")
                require('rel="next"' not in reply.headers.get("Link", ""),
                        f"Unexpected paginated GitHub response for {path}")
                return json.load(reply) if status != 204 else None
        except HTTPError as error:
            raise RuntimeError(f"GitHub {method} {path}: HTTP {error.code}") from None

    def repository(self, path):
        repository = self.call("GET", f"/repos/{path}")
        require(repository["full_name"] == path and repository["node_id"] and repository["id"] > 0,
                f"Fixture repository identity differs at {path}")
        return repository

    def ref(self, path, branch):
        ref = self.call("GET", f"/repos/{path}/git/ref/heads/{quote(branch, safe='')}")
        require(ref["ref"] == f"refs/heads/{branch}" and ref["object"]["type"] == "commit",
                f"Unexpected GitHub ref returned for {path}:{branch}")
        return ref


@dataclass
class FixtureBranch:
    repository: dict
    name: str
    sha: str

    @property
    def owner(self):
        return self.repository["owner"]["login"]

    @property
    def repo(self):
        return self.repository["full_name"]


def create_branch(api, source, branch, base_sha, base_tree, run_id, created):
    path = f"/repos/{source['full_name']}/git"
    blob = api.call("POST", f"{path}/blobs", {
        "encoding": "utf-8", "content": f"forge-mcp smoke {run_id}\n",
    }, 201)["sha"]
    tree = api.call("POST", f"{path}/trees", {
        "base_tree": base_tree,
        "tree": [{
            "path": f"forge-mcp-smoke-{run_id}.txt", "mode": "100644", "type": "blob", "sha": blob,
        }],
    }, 201)["sha"]
    require(tree != base_tree, "Smoke commit must change the base tree")
    sha = api.call("POST", f"{path}/commits", {
        "message": f"Forge-mcp fork pull smoke {run_id}",
        "tree": tree, "parents": [base_sha],
    }, 201)["sha"]
    commit = api.call("GET", f"{path}/commits/{sha}")
    require(commit["sha"] == sha and commit["tree"]["sha"] == tree
            and [parent["sha"] for parent in commit["parents"]] == [base_sha],
            "Fixture commit is not the intended direct child of the base")
    ref = api.call("POST", f"{path}/refs", {"ref": f"refs/heads/{branch}", "sha": sha}, 201)
    require(ref["ref"] == f"refs/heads/{branch}" and ref["object"]["sha"] == sha,
            f"GitHub returned an unexpected fixture branch for {branch}")
    selected = FixtureBranch(source, branch, sha)
    created.append(selected)
    require(api.ref(selected.repo, branch)["object"]["sha"] == sha,
            f"GitHub did not persist the expected fixture commit on {branch}")
    return selected


def matching_pulls(api, destination, branch, base):
    query = urlencode({"head": f"{branch.owner}:{branch.name}", "base": base,
                       "state": "all", "per_page": 100})
    pulls = api.call("GET", f"/repos/{destination['full_name']}/pulls?{query}")
    require(isinstance(pulls, list) and len(pulls) < 100,
            f"Invalid or incomplete PR readback for {branch.name}")
    return pulls


def same_pull(pull, destination, branch, base, title):
    return (pull["title"] == title
            and pull["head"]["repo"]["node_id"] == branch.repository["node_id"]
            and pull["base"]["repo"]["node_id"] == destination["node_id"]
            and pull["head"]["ref"] == branch.name and pull["base"]["ref"] == base
            and pull["head"]["sha"] == branch.sha)


def cleanup(api, destination, branches, base, title):
    failures = []
    for branch in branches:
        try:
            for pull in matching_pulls(api, destination, branch, base):
                require(same_pull(pull, destination, branch, base, title),
                        f"Refusing to clean up an unexpected pull for {branch.name}")
                if pull["state"] == "open":
                    closed = api.call(
                        "PATCH", f"/repos/{destination['full_name']}/pulls/{pull['number']}",
                        {"state": "closed"},
                    )
                    require(closed["state"] == "closed" and closed["id"] == pull["id"],
                            f"Could not verify cleanup of pull #{pull['number']}")
            require(api.ref(branch.repo, branch.name)["object"]["sha"] == branch.sha,
                    f"Refusing to delete a changed fixture branch {branch.name}")
            api.call("DELETE", f"/repos/{branch.repo}/git/refs/heads/{quote(branch.name, safe='')}",
                     status=204)
        except (RuntimeError, KeyError, TypeError, ValueError, URLError) as error:
            failures.append(str(error))
    require(not failures, f"Fixture cleanup failed: {', '.join(failures)}")


def build_binaries(checkout, expected_head, work, env):
    actual_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout,
                                          env=env, text=True).strip()
    require(actual_head == expected_head, f"Expected PR head {expected_head}, found {actual_head}")
    require(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                        cwd=checkout, env=env),
            "Smoke requires a clean checkout of the exact attested PR head")
    target = work / "cargo"
    build_env = dict(env, CARGO_TARGET_DIR=str(target), TMPDIR=str(work))
    subprocess.run(["cargo", "build", "--bin", "server", "--bin", "transport"],
                   cwd=checkout, env=build_env, check=True)
    return target / "debug" / "server", target / "debug" / "transport"


@contextmanager
def gateway(binary, work, env, api_token, destination, source):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    address = f"127.0.0.1:{port}"
    token_file = work / "agent.token"
    token_file.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    config = work / "forge-mcp.toml"
    config.write_text(f"""
[server]
listen = {json.dumps(address)}
[[forges]]
alias = {json.dumps(ALIAS)}
type = "github"
base_url = "https://github.com"
token = {json.dumps(api_token)}
[[agents]]
token = {json.dumps(token_file.read_text(encoding="utf-8"))}
agent_id = "github-fork-smoke"
session_id = "ci"
[agents.policy]
allowed_repos = {json.dumps([ALIAS + "/" + destination, ALIAS + "/" + source])}
branch_prefix = {json.dumps(PREFIX)}
""", encoding="utf-8")
    # Credentials are in a private temporary directory, never in process
    # arguments. The gateway receives only its own scoped upstream credential.
    process = subprocess.Popen([binary, config], env=env, stdout=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + TIMEOUT
        while True:
            require(process.poll() is None, "Smoke gateway exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                require(time.monotonic() < deadline, "Timed out waiting for smoke gateway")
                time.sleep(0.1)
        yield f"http://{address}", token_file
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


async def tool_call(shim, env, url, token_file, arguments):
    process = await asyncio.create_subprocess_exec(
        shim, "--gateway-url", url, "--token-file", token_file, env=env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
    )

    async def send(method, params, request_id=None):
        frame = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            frame["id"] = request_id
        process.stdin.write((json.dumps(frame) + "\n").encode())
        await process.stdin.drain()
        if request_id is not None:
            async with asyncio.timeout(TIMEOUT * 5):
                while line := await process.stdout.readline():
                    response = json.loads(line)
                    if response.get("id") == request_id:
                        return response
            raise RuntimeError("MCP shim closed before responding")

    try:
        initialized = await send("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "github-fork-smoke", "version": "1"},
        }, 1)
        require(initialized.get("result", {}).get("protocolVersion") == "2025-06-18",
                "MCP initialization failed")
        await send("notifications/initialized", {})
        return await send("tools/call", {"name": "open_change_request", "arguments": arguments}, 2)
    finally:
        process.stdin.close()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await asyncio.wait_for(process.wait(), timeout=5)


def invoke(shim, env, connection, destination, branch, base, title):
    owner, repo = destination["full_name"].split("/")
    return asyncio.run(tool_call(shim, env, *connection, {
        "forge": ALIAS, "owner": owner, "repo": repo, "head_repo": branch.repository["name"],
        "head_branch": f"{branch.owner}:{branch.name}", "base_branch": base,
        "title": title, "body": "Disposable protected CI fixture.",
    }))


def exercise(api, shim, env, connection, fixture, base, title, base_sha):
    destination, admitted, bad_prefix, ungranted = fixture
    for branch in (admitted, bad_prefix, ungranted):
        require(not matching_pulls(api, destination, branch, base),
                f"Fixture branch already has a matching PR: {branch.name}")
    frame = invoke(shim, env, connection, destination, admitted, base, title)
    result = frame.get("result", {})
    require(result.get("isError") is False, "MCP qualified pull creation failed")
    tool_number = json.loads(result["content"][0]["text"])["index"]
    pulls = matching_pulls(api, destination, admitted, base)
    require(len(pulls) == 1, f"Expected one new pull across all states, found {len(pulls)}")
    pull = pulls[0]
    require(pull["number"] == tool_number and same_pull(pull, destination, admitted, base, title)
            and pull["base"]["sha"] == base_sha and pull["state"] == "open",
            "Independent GitHub readback differs from the requested pull")

    rejected = {}
    for branch, case, message in [
        (bad_prefix, "disallowed_prefix", "does not start with required prefix"),
        (ungranted, "ungranted_source", "is not authorized for repository"),
    ]:
        frame = invoke(shim, env, connection, destination, branch, base, title)
        error = frame.get("error", {})
        require(error.get("code") == -32602 and message in error.get("message", ""),
                f"Expected an explicit policy rejection for {case}")
        count = len(matching_pulls(api, destination, branch, base))
        require(count == 0, f"GitHub found {count} PRs for policy rejection {case}")
        rejected[case] = {
            "repository_id": branch.repository["node_id"], "ref": branch.name,
            "sha": branch.sha, "policy_error": error["code"], "matching_pulls": count,
        }

    return {
        "pull_number": pull["number"], "pull_url": pull["html_url"],
        "matching_pulls_before": 0, "matching_pulls_after": len(pulls),
        "head": {"repository": admitted.repo, "id": admitted.repository["node_id"],
                 "ref": admitted.name, "sha": admitted.sha},
        "base": {"repository": destination["full_name"], "id": destination["node_id"],
                 "ref": base, "sha": base_sha},
        "rejections": rejected,
    }


def smoke(checkout, work):
    head = setting("HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", head), "Set HEAD to the full attested PR commit SHA")
    destination_path = repo_setting("UPSTREAM")
    source_path = repo_setting("FORK")
    ungranted_path = repo_setting("UNGRANTED_FORK")
    base = setting("BASE")
    fixture_token = setting("FIXTURE_TOKEN")
    gateway_token = setting("GATEWAY_TOKEN")
    require(fixture_token != gateway_token, "Fixture and gateway credentials must be distinct")
    require(len({path.split("/")[0].lower() for path in
                 (destination_path, source_path, ungranted_path)}) == 3,
            "Use separate fixture owners for upstream, admitted fork, and ungranted fork")
    # Build and child processes inherit no job secrets. The protected CI job
    # authorizes this specific reviewed SHA before it provisions credentials.
    env = {key: os.environ[key] for key in ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME")
           if key in os.environ}
    server, shim = build_binaries(checkout, head, work, env)

    api = GitHub(fixture_token)
    gateway_api = GitHub(gateway_token)
    destination, source, ungranted = [
        api.repository(path) for path in (destination_path, source_path, ungranted_path)
    ]
    require(not destination["fork"] and all(
        fork["fork"] and fork["source"]["node_id"] == destination["node_id"]
        for fork in (source, ungranted)
    ), "Both fixture forks must belong to the upstream root network")
    for repository in (destination, source, ungranted):
        require(gateway_api.repository(repository["full_name"])["node_id"] == repository["node_id"],
                "Gateway credential must be able to read all three fixture repositories")
    sha = api.ref(destination_path, base)["object"]["sha"]
    tree = api.call("GET", f"/repos/{destination_path}/git/commits/{sha}")["tree"]["sha"]

    run_id = secrets.token_hex(12)
    title = f"Forge-mcp GitHub fork pull smoke {run_id}"
    branches = []
    try:
        admitted = create_branch(api, source, f"{PREFIX}{run_id}-admitted",
                                 sha, tree, run_id, branches)
        bad_prefix = create_branch(api, source, f"outside-smoke/{run_id}-prefix",
                                    sha, tree, run_id, branches)
        denied = create_branch(api, ungranted, f"{PREFIX}{run_id}-denied",
                                sha, tree, run_id, branches)
        fixture = (destination, admitted, bad_prefix, denied)
        with gateway(server, work, env, gateway_token, destination_path, source_path) as connection:
            result = exercise(api, shim, env, connection, fixture, base, title, sha)
    finally:
        cleanup(api, destination, branches, base, title)
    print(json.dumps({"implementation_head": head, "run_id": run_id, **result}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path,
                        help="clean checkout of the exact approved implementation PR head")
    parser.add_argument("--scratch", required=True, type=Path,
                        help="runner-local scratch directory outside the checkout")
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    scratch = args.scratch.resolve()
    require(scratch != checkout and checkout not in scratch.parents,
            "Use a scratch directory outside the implementation checkout")
    with tempfile.TemporaryDirectory(prefix="github-fork-smoke-", dir=scratch) as directory:
        smoke(checkout, Path(directory))


if __name__ == "__main__":
    main()
