# Pinned data-plane inputs

`artifacts.lock.json` contains reviewed **laboratory candidates**, not a production
installer. It has no keys, UUIDs, domains, client profiles, or provider tokens.

Fetch an artifact into the ignored private directory:

```bash
go run ./cmd/artifact-fetch \
  -lock deploy/data-plane/artifacts.lock.json \
  -name xray-linux-amd64 \
  -out-dir .local/artifacts
```

The command refuses unknown fields, non-HTTPS URLs, unapproved hosts, redirects to
unapproved hosts, oversized responses, digest mismatches, path traversal, duplicate
entries, and overwrites. Successful download verification does not authorize
execution. Build or extraction happens in a later reviewed stage.

To update the lock:

1. start from a signed or otherwise authenticated upstream tag;
2. record the immutable commit SHA behind the tag;
3. independently download and hash the exact asset;
4. compare vendor-provided digests where available;
5. review upstream security issues and release status;
6. update the evidence cutoff and run the complete test suite;
7. promote only through canaries with an automatic rollback criterion.
