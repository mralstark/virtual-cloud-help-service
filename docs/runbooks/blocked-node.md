# Runbook: suspected blocked or degraded node

## Trigger

Open an incident when opt-in full-transfer probes show a sustained, statistically
meaningful regression for one endpoint, IP, subnet, ASN, transport, or operator.
Handshake-only failures are insufficient to distinguish blocking from an outage.

## Containment

1. Confirm the control plane, provider status, capacity, certificate time, DNS, and
   host firewall from outside the affected network.
2. Compare coarse failure classes across at least one unaffected network. Do not
   request packet captures from ordinary users.
3. Stop new selection of the endpoint by increasing its priority or remove it in a
   higher catalog revision. Keep established tunnels until the drain deadline.
4. Provision a canary on a different provider and ASN with newly generated
   per-device credentials. Do not copy the old node image or credentials.
5. Publish the replacement and verify signature, version, expiry, discovery mirrors,
   UDP-disabled fallback, and a full bidirectional transfer.

## Rotation

Roll out to opt-in canaries, then 10%, 25%, 50%, and 100% only while success and
latency stay within the current SLO. At each step retain an independent transport
and provider path. Roll back automatically on transfer-stall or leak-test failures.

After at least one manifest lifetime plus the maximum client offline grace period,
revoke old credentials, destroy the node, and confirm deletion through the provider.

## Evidence and privacy

Record incident timestamps, catalog revisions, anonymous aggregate counts, provider,
ASN, transport, and coarse operator/region labels. Do not store browsing
destinations, DNS queries, payloads, SNI, or full client IP addresses. Delete raw
canary diagnostics according to the short incident retention policy.

## Post-incident

Classify the failure as service outage, capacity, DNS, UDP loss, IP/subnet/ASN block,
TLS classification, partial-transfer interference, or unknown. Update the test
matrix and cooldown policy only when repeated measurements support the change.
