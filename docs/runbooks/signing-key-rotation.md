# Runbook: online manifest signing-key rotation

The offline root private key is the trust anchor. It must not be present on the
control-plane host, in CI, in a container image, or in ordinary backups. This runbook
rotates an online manifest key; rotating the offline root is not implemented.

## Prepare

1. Record the current durable manifest version `N`, key-policy version `P`, policy
   digest, signing key ID/epoch, and catalog revision from the protected state backup.
2. Choose a cutover version `C` far enough ahead for at least one full manifest TTL
   and the documented offline-client grace window. `C` must be greater than `N`.
3. Generate the replacement online Ed25519 key on Linux. Store its private key in
   the production secret manager and copy only its public key to the offline policy
   workstation.
4. Create grants with contiguous ranges: the current key keeps its existing start
   and ends at `C`; the replacement starts at `C+1`, uses the next epoch, and is
   open-ended. No ranges may overlap or contain gaps.
5. With the offline root, create policy version `P+1` into a new file:

```bash
go run ./cmd/manifest-key-policy \
  -root-private /offline/manifest-root.key \
  -grants /offline/key-grants-P-plus-1.json \
  -policy-version P_PLUS_1 \
  -out /offline/manifest-key-policy-P-plus-1.json
```

Verify the printed root key ID against two independently stored records. Have a
second operator review the grants, public-key fingerprints, policy version, and
cutover.

## Propagate before cutover

1. Deploy the new public policy file while the old online key is still authorized.
   Do not deploy the new private key yet.
2. Confirm newly issued manifests contain policy `P+1`, remain signed by the old key,
   and advance the durable policy digest without changing the signing epoch.
3. Observe opt-in clients for at least one TTL plus the offline grace window. Clients
   must persist policy `P+1`; a return to `P` must fail as rollback.
4. Back up the signing key, new policy, and issuer state atomically. Test restore on
   an isolated host without publishing a manifest.

## Cut over

1. Stop the single active issuer before it attempts version `C+1`.
2. Replace only the online signing-key secret with the new private key. Keep the
   same durable state and policy `P+1`.
3. Start one issuer. It must allocate exactly `C+1`, select the next policy epoch,
   persist state, and then publish.
4. Verify the envelope from every discovery mirror using the pinned offline root and
   a trusted state from before cutover. Run expiry, rollback, same-version
   equivocation, and full client discovery tests.
5. Keep the retired private key quarantined offline until the rollback decision
   window closes; never re-enable it after `C`.

## Failure handling

- If startup says the key is unauthorized, stop. Do not delete or edit issuer state.
- If any mirror serves a different payload at the same version, remove it and open a
  security incident.
- If cutover has not published `C+1`, restore the previous process/key and continue
  only up to `C`. Correct the policy with a new, higher policy version.
- After `C+1` is published, rollback to the old key is prohibited. Repair forward
  with the new key or create another higher offline-root policy.
