
---

# 🤝 docs/CONTRIBUTING.md

```markdown
# Contributing Guidelines

## Adding a new scanner
1. Create a new worker under `workers/`
2. Write a Dockerfile wrapping the tool
3. Ensure it outputs normalized JSON schema
4. Add Kubernetes Job template
5. Document it under `docs/SCANNERS.md`

## Coding style
- Python: black, mypy
- Node: eslint, prettier

## Pull requests
- Fork → feature branch → PR
- Add docs/tests for new scanners or agents
