---
name: MVP Task
about: MVP implementation task template with TDD and Definition of Done
title: "[MVP] "
labels: ["mvp", "tdd"]
assignees: []
---

## Summary
- What we are building:
- Why this task matters:

## Scope
- In scope:
- Out of scope:

## Dependencies
- Blocked by:
- Blocks:

## TDD Plan
1. Write a failing test first (`RED`)
2. Implement minimum code to pass (`GREEN`)
3. Refactor while keeping tests green (`REFACTOR`)

## Test Cases
- [ ] Unit test cases listed
- [ ] Contract test cases listed (if API-related)
- [ ] Integration test cases listed (if service-related)
- [ ] E2E test cases listed (if UI flow-related)

## Implementation Tasks
- [ ] Task 1
- [ ] Task 2
- [ ] Task 3

## Definition of Done (DoD)
- [ ] Scope is fully implemented
- [ ] Tests were written first and failure was confirmed
- [ ] All new/updated tests pass locally
- [ ] Lint/format checks pass
- [ ] Backward compatibility is preserved or documented
- [ ] Docs/config were updated if needed
- [ ] Demo steps or verification notes are attached to the issue/PR

## Verification Commands
```bash
# Example (replace with actual commands)
pnpm test
pnpm lint
cargo test
cargo clippy -- -D warnings
```

## Risks / Notes
- Risk:
- Mitigation:

