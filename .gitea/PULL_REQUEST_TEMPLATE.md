## Change type

- [ ] New service / stack
- [ ] Service configuration change
- [ ] OIDC / auth integration
- [ ] Container image or runtime change
- [ ] Workflow / CI change
- [ ] Infrastructure (Traefik, Komodo, runner)
- [ ] Dependency update
- [ ] Documentation only

## Design goal

What the change achieves and why.

## Acceptance criteria

- Observable outcome that defines success.

## Change narrative

### What changed and why

File-by-file or logical-group explanation of what was modified and the reasoning.

### Execution path

How this config/code gets consumed at runtime: startup order, service
dependencies, network flow, secret injection path.

### Upstream assumptions

Which upstream service version or documentation this targets, with links.

## Risk assessment

### Impact

Which services, deploys, workflows, or operators are affected.

### Security

Auth, secrets, network, privilege, or workflow implications.

### Open questions

Anything uncertain or that could not be verified.

## Non-goals

What is explicitly out of scope.

## References

- Upstream docs consulted
- Repo file paths referenced (e.g. `docs/agents/auth.md`)
