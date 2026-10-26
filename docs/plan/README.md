# auth1 1.0 — Implementation plan

The plan lives in **GitHub issues**, not in this repository:

| Level | Where |
|---|---|
| Roadmap | [#69 auth1 1.0 roadmap](https://github.com/arafat-hasan/auth1/issues/69) (pinned): goal, global constraints G-1 … G-9, Go practices, milestones, review focus |
| Milestones | Issues [#60](https://github.com/arafat-hasan/auth1/issues/60) … [#68](https://github.com/arafat-hasan/auth1/issues/68), and GitHub milestones `M0` … `M8` |
| Work packages | 57 issues labelled `work-package`, `WP-00` … `WP-93`, each with scope, references, *done when* checklist and *blocked by* links |

Conventions:
- **Sub-issues:** each milestone issue is a sub-issue of the roadmap, and each work package is a sub-issue of its milestone.
- **Step plans:** a work package's step-level plan (files, signatures, tests) is added to its issue under `## Steps` when the work starts.
- **Branches and PRs:** branch `wp-NN-<slug>`; one PR per work package, saying `Closes #<issue>`.
- **Changing the plan:**
  - Changing scope or order: edit the issue and comment on what changed and why.
  - A change that contradicts [the SDD](../design.md) or [a TDD](../tdd/) changes the design document first, in a PR.
- **Labels:** `area:<name>` and `tdd:01` … `tdd:08` let the issue list be filtered by area or by the TDD implemented.
