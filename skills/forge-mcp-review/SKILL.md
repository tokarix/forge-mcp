---
name: forge-mcp-review
description: Use when reviewing pull requests or change requests through the forge-mcp gateway, especially when the review should be posted back to the PR and commit hygiene matters
---

# forge-mcp Review

Use this skill for PR review work done through forge-mcp.

## Workflow

1. **Prefer lean memory patterns**. Rely on your coordinator's injected `memory_rules` and do not load full recall-heavy context. Use targeted `memory_rules(tags=[...])` if you need to pull in specific required context like git and commit-hygiene rules. Use `memory_search(...)` selectively when exploring unfamiliar project components.
3. Call `forge_info` first to learn the forge alias and confirm the active forge-mcp identity.
4. Resolve the PR target before reviewing:
   - If the user already gave a PR index, use it.
   - If no PR index was given, call `list_change_requests` with `state: "open"`.
   - If there are no open PRs, tell the user and stop.
   - If there is exactly one open PR, review that PR.
   - If there are multiple open PRs, present a short list and ask the user which PR to review. Prefer a selectable `request_user_input` prompt when available; otherwise ask a concise plain-text question.
4. Read PR metadata with `get_change_request` before reviewing. Capture at least the title, body, changed file count, and current `head_sha`.
5. Read the patch with `get_change_request_diff`.
6. Read existing discussion with `get_change_request_comments` before drafting findings so you can see prior reviews, avoid duplicate stale findings, and notice whether the PR changed since earlier review comments. **Do not defer your review based on prior approvals** — always perform your own independent analysis regardless of other agents' verdicts.
7. Inspect the PR branch through the git proxy and run `git log --oneline <merge_base>..HEAD` to inspect the commit series. Prefer fetching the PR branch into an existing local repo and creating a detached `git worktree` for review so objects are reused without touching the active worktree. Fall back to a fresh clone only when no suitable local repo is available. This is required for evaluating commit hygiene regardless of diff size.
8. Optionally, if the runtime supports subagents, delegate the review pass to a subagent using the prompt template below. Otherwise, perform the review directly in the main agent context.
9. Validate the highest-signal findings locally, run verification if needed.
10. **Submit the formal review verdict.** Call `submit_change_request_review` with the appropriate verdict (`APPROVED`, `REQUEST_CHANGES`, or `COMMENT`) and a body summarizing the findings. The review is **not complete** until this tool call succeeds — reporting findings in chat alone does not record the verdict on the Forge.
11. **Clean up temporary directories.** After posting the review, remove any worktrees and clones created during the review. If you created a detached worktree with `git worktree add`, remove it with `git worktree remove`. If you cloned into `/tmp`, remove the clone directory with `rm -rf`. This prevents `/tmp` from filling up across multiple reviews.

## Required forge-mcp Tools

- `forge_info` to discover the forge alias and active identity.
- `get_change_request` to read the current PR metadata and head SHA.
- `get_change_request_comments` to read existing comments and formal reviews.
- `get_change_request_diff` to inspect the actual patch.
- `list_change_requests` to resolve the review target when the user did not specify a PR number.
- `submit_change_request_review` to post the formal result.

Use `comment_on_change_request` only as a fallback when a formal review cannot be posted because of forge-side restrictions.

## PR Selection Rules

- When multiple open PRs exist, present only a short disambiguation list.
- Keep the list easy to scan: PR index, title, and optionally head branch or author if needed to disambiguate.
- Do not guess which PR the user meant when several are open.
- Do not start review work on one PR and ask later; resolve the target first.

## Review Posting Rules

- If the user asks to review a PR, post a review to the PR instead of stopping at local analysis.
- Use `REQUEST_CHANGES` for blocking bugs, regressions, missing required tests, or commit-hygiene violations.
- Use `APPROVED` when there are no blocking findings.
- Use `COMMENT` for non-blocking follow-up notes or when a formal approval/change-request verdict is not appropriate.

## Independent Review Policy

Every review agent must perform its own independent analysis of the PR.
Do not skip or abbreviate a review because another agent already approved.

- **Read prior reviews** to avoid posting duplicate findings and to
  understand context, but form your own conclusions.
- **Different agents bring different capabilities.** Your tool access,
  domain knowledge, and failure-mode coverage may differ from other
  reviewers. A prior approval does not mean the PR is free of issues
  you can detect.
- **Submit your own verdict** based on your findings, not on agreement
  or disagreement with prior reviewers.

### When to Skip a Review

Skip the review **only** when one of the following applies:

- CI is failing — the PR is not yet in a reviewable state.
- The PR has been closed or rejected.
- The operator or user explicitly told you to defer.

A prior approval from another agent is **not** a reason to skip.

## Required Review Criteria

Commit hygiene is review-blocking when violated. Always inspect the PR
branch via the git proxy and inspect the commit series with `git log`
to verify structure — the final diff alone cannot reveal fixup churn,
revert/re-add cycles, or unrelated changes split across commits.

Preferred local workflow:
- If a suitable local checkout of the repo already exists, fetch the PR branch through the git proxy into that repo.
- Create a detached `git worktree` for the PR head and review there.
- Do not switch the active worktree to the PR branch, especially if it may be dirty.
- Use a full fresh clone only as a fallback when no suitable local repo is available.

- Each commit must be self-contained, minimal, and logically independent.
- Never accept unrelated changes mixed into one commit.
- Follow Linux kernel-style patch hygiene: small commits, one thing per commit, with clear what/why commit messages.

## Addressing Review Feedback on Your Own PRs

When a reviewer posts `REQUEST_CHANGES` on a PR you authored:

1. Read the review with `get_change_request_comments` to understand all findings.
2. For each finding, make the fix locally and generate a patch with `git diff --no-ext-diff --binary`.
3. Submit each fix with `commit_patch` using `existing_branch: true`.
4. After all fixes are pushed, use `rebase_branch` to squash fixup commits into the correct logical commits. The final series must have clean, self-contained commits — never leave fixup-style follow-ups.
5. Fetch the branch and verify the commit series with `git log` before considering the work done.

**Never ask the user to run git commands manually.** All operations — committing, squashing, and force-pushing — are handled by forge-mcp tools.

## Suggested Subagent Prompt

Use this template when delegating to a subagent. When the runtime does
not support subagent delegation, follow the same focus areas directly.

```text
Review PR #<n> in <owner>/<repo> on forge alias <forge>. Current head SHA: <head_sha>.

Use forge-mcp review tools as needed:
- forge_info
- get_change_request
- get_change_request_comments
- get_change_request_diff
- submit_change_request_review

If your runtime uses the memory-server, pull in strictly relevant rules via `memory_rules(tags=...)` rather than loading noisy general project recall.

Focus on bugs, regressions, missing tests, and commit hygiene.

Treat these git rules as mandatory review criteria:
- Each commit must be self-contained, minimal, and logically independent.
- Never accept unrelated changes mixed into one commit.
- Follow Linux kernel-style patch hygiene: small commits, one thing per commit, with clear what/why commit messages.

Always inspect the PR branch via the git proxy and inspect the commit
series with git log. Prefer fetch + detached worktree from an existing
repo over a fresh clone, and do not switch the active worktree to the
PR branch. The final diff alone cannot reveal commit-structure problems.

Read the current PR metadata, diff, and existing comments/reviews before concluding.
Do not skip or abbreviate the review because another agent already approved.
Read prior reviews to avoid duplicate findings, but perform your own
independent analysis and submit your own verdict.
Call out commit-structure violations as findings, not optional notes.

You MUST call `submit_change_request_review` with the verdict (APPROVED,
REQUEST_CHANGES, or COMMENT) and a body summarizing findings. The review
is not complete until this tool call succeeds.

After posting the review, clean up: remove any git worktrees you created
with `git worktree remove` and delete any /tmp clone directories with
`rm -rf`. Do not leave temporary directories behind.
```
