---
name: forge-mcp-review
description: Use when reviewing pull requests or change requests through the forge-mcp gateway, especially when the review should be posted back to the PR and commit hygiene matters
---

# forge-mcp Review

Use this skill for PR review work done through forge-mcp.

## Workflow

1. Load project memory rules first, especially git and commit-hygiene rules.
2. Call `forge_info` first to learn the forge alias and confirm the active forge-mcp identity.
3. Resolve the PR target before reviewing:
   - If the user already gave a PR index, use it.
   - If no PR index was given, call `list_change_requests` with `state: "open"`.
   - If there are no open PRs, tell the user and stop.
   - If there is exactly one open PR, review that PR.
   - If there are multiple open PRs, present a short list and ask the user which PR to review. Prefer a selectable `request_user_input` prompt when available; otherwise ask a concise plain-text question.
4. Read PR metadata with `get_change_request` before reviewing. Capture at least the title, body, changed file count, and current `head_sha`.
5. Read the patch with `get_change_request_diff`.
6. Read existing discussion with `get_change_request_comments` before drafting findings so you can see prior reviews, avoid duplicate stale findings, and notice whether the PR changed since earlier review comments.
7. Clone the PR branch via the git proxy and run `git log --oneline <merge_base>..HEAD` to inspect the commit series. This is required for evaluating commit hygiene regardless of diff size.
8. Optionally, if the runtime supports subagents, delegate the review pass to a subagent using the prompt template below. Otherwise, perform the review directly in the main agent context.
9. Validate the highest-signal findings locally, run verification if needed, and then post the review back to the PR.

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

## Required Review Criteria

Commit hygiene is review-blocking when violated. Always clone the PR
branch via the git proxy and inspect the commit series with `git log`
to verify structure — the final diff alone cannot reveal fixup churn,
revert/re-add cycles, or unrelated changes split across commits.

- Each commit must be self-contained, minimal, and logically independent.
- Never accept unrelated changes mixed into one commit.
- Follow Linux kernel-style patch hygiene: small commits, one thing per commit, with clear what/why commit messages.

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

Focus on bugs, regressions, missing tests, and commit hygiene.

Treat these git rules as mandatory review criteria:
- Each commit must be self-contained, minimal, and logically independent.
- Never accept unrelated changes mixed into one commit.
- Follow Linux kernel-style patch hygiene: small commits, one thing per commit, with clear what/why commit messages.

Always clone the PR branch via the git proxy and inspect the commit
series with git log. The final diff alone cannot reveal commit-structure
problems.

Read the current PR metadata, diff, and existing comments/reviews before concluding.
Call out commit-structure violations as findings, not optional notes.
```
