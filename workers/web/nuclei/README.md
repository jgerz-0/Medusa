# Medusa Nuclei Worker

This worker executes [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei)
scans inside an isolated container. Jobs are received from Redis, normalized, and
reported back to the controller. See `worker.py` for details.

## Redis Queues

The controller enqueues scan jobs onto Redis list channels that the worker
polls continuously:

* `queues:nuclei:jobs` — primary queue where the controller publishes new nuclei jobs.
* `queues:nuclei:dead` — dead-letter queue for jobs that exhaust retries or fail fatally.

These defaults are shared between the controller (`Settings.nuclei_queue_channel`)
and the worker (`WorkerConfig.queue_key` and `WorkerConfig.dead_letter_key`) so the
services remain interoperable. Override the Redis channel names by setting the
`NUCLEI_QUEUE_KEY` and `NUCLEI_DEAD_LETTER_KEY` environment variables on the worker
deployment when custom routing is required.
