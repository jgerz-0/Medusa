# Nuclei Web Worker

This worker encapsulates the Nuclei scanner with hardened configuration for Medusa deployments.
It will receive scoped JSON jobs from the controller, execute deterministic scans, and enrich
results with CVE metadata before publishing back to the message bus.
