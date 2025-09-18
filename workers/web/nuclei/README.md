# Medusa Nuclei Worker

This worker executes [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei)
scans inside an isolated container. Jobs are received from Redis, normalized, and
reported back to the controller. See `worker.py` for details.
