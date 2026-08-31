data "twc_configurator" "frankfurt" {
  location = "de-1"
  # Frankfurt currently exposes the Premium configurator. The availability zone
  # remains fra-1 on the server resource.
  preset_type = "premium"
}

data "twc_os" "ubuntu" {
  family  = "linux"
  name    = "ubuntu"
  version = "24.04"
}

resource "twc_ssh_key" "pilot" {
  name       = "${var.project_name}-admin"
  body       = trimspace(file(var.ssh_public_key_path))
  is_default = false
}

resource "twc_server" "pilot" {
  name                      = var.server_name
  hostname                  = var.server_name
  comment                   = "Disposable single-node Amnezia pilot"
  project_id                = var.timeweb_project_id
  os_id                     = data.twc_os.ubuntu.id
  availability_zone         = "fra-1"
  ssh_keys_ids              = [twc_ssh_key.pilot.id]
  is_root_password_required = false
  cloud_init = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_cidr     = var.admin_cidr
    awg_port       = var.awg_port
    reality_port   = var.reality_port
    ssh_public_key = trimspace(file(var.ssh_public_key_path))
  })

  configuration {
    configurator_id = data.twc_configurator.frankfurt.id
    cpu             = var.cpu
    ram             = var.ram_mb
    disk            = var.disk_mb
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.cpu <= 2 && var.ram_mb <= 4096 && var.disk_mb <= 40 * 1024
      error_message = "Pilot cost guard exceeded: review and change the guard explicitly."
    }
  }
}

resource "twc_firewall" "pilot" {
  name        = "${var.project_name}-edge"
  description = "Attached cloud firewall; host nftables remains authoritative"

  link {
    id   = twc_server.pilot.id
    type = "server"
  }

  lifecycle {
    postcondition {
      condition     = self.policy == "DROP"
      error_message = "Timeweb firewall default policy is not DROP; do not expose the pilot until reviewed."
    }
  }
}

resource "twc_firewall_rule" "ssh" {
  firewall_id = twc_firewall.pilot.id
  direction   = "ingress"
  protocol    = "tcp"
  port        = "22"
  cidr        = var.admin_cidr
  description = "SSH from the single approved administrator address"
}

resource "twc_firewall_rule" "amneziawg" {
  firewall_id = twc_firewall.pilot.id
  direction   = "ingress"
  protocol    = "udp"
  port        = tostring(var.awg_port)
  cidr        = "0.0.0.0/0"
  description = "Observed AmneziaWG port; must match official client setup"
}

resource "twc_firewall_rule" "reality" {
  firewall_id = twc_firewall.pilot.id
  direction   = "ingress"
  protocol    = "tcp"
  port        = tostring(var.reality_port)
  cidr        = "0.0.0.0/0"
  description = "Observed XRay Reality port; must match official client setup"
}

resource "twc_firewall_rule" "icmp" {
  firewall_id = twc_firewall.pilot.id
  direction   = "ingress"
  protocol    = "icmp"
  cidr        = "0.0.0.0/0"
  description = "Rate limiting remains the responsibility of the host/provider"
}

resource "twc_firewall_rule" "egress_tcp" {
  firewall_id = twc_firewall.pilot.id
  direction   = "egress"
  protocol    = "tcp"
  port        = "1-65535"
  cidr        = "0.0.0.0/0"
  description = "VPN and host outbound TCP"
}

resource "twc_firewall_rule" "egress_udp" {
  firewall_id = twc_firewall.pilot.id
  direction   = "egress"
  protocol    = "udp"
  port        = "1-65535"
  cidr        = "0.0.0.0/0"
  description = "VPN, DNS, and time synchronization outbound UDP"
}

resource "twc_firewall_rule" "egress_icmp" {
  firewall_id = twc_firewall.pilot.id
  direction   = "egress"
  protocol    = "icmp"
  cidr        = "0.0.0.0/0"
  description = "Path MTU discovery and diagnostics"
}
