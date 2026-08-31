# Timeweb Cloud Frankfurt pilot

This directory describes a **billable**, disposable Timeweb Cloud server. Running
`terraform plan` is read-only; running `terraform apply` creates paid resources and
always requires the account owner's explicit approval.

## Security boundaries

- Use a dedicated Ed25519 SSH key and a single trusted IPv4 `/32` admin CIDR.
- Reuse a dedicated existing Timeweb project and scope the API token to that project.
- Supply the least-privilege, short-lived API token only as `TWC_TOKEN`; cloud
  server and network management are sufficient for this stack.
- Never put a token, private key, real IP, or domain secret in this directory.
- Review the generated plan and current Timeweb price before applying it.
- Confirm `fra-1` has immediately available capacity. Do not apply while the panel
  offers only a preorder unless the owner explicitly accepts an unbounded wait.
- The cloud-init file installs only host hardening. It deliberately does not fetch
  unpinned VPN binaries from the Internet.
- The attached Timeweb firewall does not replace nftables. Confirm its default DROP
  policy and rules in the panel before exposing the host.
- Timeweb's managed cloud-server DDoS option is not available in Frankfurt. The
  pilot must not set `is_ddos_guard`; use the cloud firewall and host controls and
  record this limitation in the demonstration report.

## Validate without creating resources

```powershell
Copy-Item terraform.tfvars.example terraform.tfvars
# Replace the example path, CIDR, and existing Timeweb project ID with local values.
$env:TWC_TOKEN = '<short-lived-token>'
terraform init
terraform fmt -check
terraform validate
terraform plan
```

Do not run `terraform apply` until the plan, monthly price, location, DDoS limitation,
firewall behavior, and deletion policy have been reviewed. A strict destination
allowlist still requires the customer or network operator to approve the resulting
IP/domain.

Continue with the reviewed steps in
[`docs/runbooks/timeweb-pilot-demo.md`](../../docs/runbooks/timeweb-pilot-demo.md).
The sample catalog uses documentation-only addresses and ASN `64496`; replace the
ASN with the value measured for the allocated Timeweb IP before signing it.
