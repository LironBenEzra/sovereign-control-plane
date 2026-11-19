# Engineering Standards — Python

Optimize for correctness, maintainability, readability, and reviewability, not maximum abstraction or minimum line count.

## Before changing code
- Read the relevant files, tests, and `pyproject.toml`; follow existing architecture, conventions, and Python version.
- Understand the requested behavior and identify the smallest coherent change. For nontrivial work, briefly outline the approach and trade-offs first.
- Do not add dependencies, layers, patterns, or public APIs without a concrete need. Avoid unrelated refactoring.

## Design: pragmatic, idiomatic Python
- Prefer plain functions for stateless operations. Introduce classes only for meaningful state, invariants, cohesive behavior, or lifecycle management.
- Use `Protocol` for structural interfaces at real substitution/testing boundaries. Use `ABC` when a formal runtime contract or shared base behavior is truly needed. Never create an interface merely to mirror one implementation.
- Prefer composition and dependency injection over deep inheritance or global state. Keep business logic separate from I/O and framework glue when it improves testability.
- Favor small, cohesive modules and functions, explicit data flow, descriptive names, and early returns. Avoid speculative flexibility and design-pattern ceremony.
- Use `dataclass` for simple structured data when appropriate; use the project's existing validation models for external input.

## Code quality
- Add precise type hints to new/changed public interfaces and important internal boundaries; avoid unjustified `Any` and opaque return types.
- Use explicit, meaningful exceptions and appropriate error handling. Never swallow exceptions silently or log secrets.
- Comments should explain *why* or non-obvious constraints, not restate *what* clear code does.
- Preserve backwards compatibility and existing behavior unless the request explicitly requires a change.
- Prefer a focused, easy-to-review diff; remove unused code/imports introduced by your changes.

## Verification and handoff
- Add or update focused pytest tests for nontrivial behavior, including edge cases and error paths; avoid brittle tests of implementation details.
- Run the repository's documented formatting, lint, type-checking, and test commands. If not configured, report the gap; do not claim tests passed without running them.
- Before finishing, review your own diff for correctness, unnecessary abstractions, hidden coupling, naming, and reviewer cognitive load.
- Final response: summarize design decisions, changed files, commands run and results, and any risks or unfinished checks. Be concise.
