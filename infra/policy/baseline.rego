package medusa.ci

# Default deny rule for CI policy gate. Extend with domain-specific deny
# rules that return human-readable violation messages when guardrails are
# breached. Leaving this as false ensures the pipeline passes until
# contributors define explicit denies.
default deny = false
