# Persistent volumes

This directory holds Docker Compose bind mounts for the local development stack.
It is safe to remove when you want a clean slate; `docker compose down -v`
recreates each service's data store on the next `up` run.
