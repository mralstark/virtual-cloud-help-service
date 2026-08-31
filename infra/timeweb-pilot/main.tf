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
  comment                   = "Disposable allowlist/DPI-resilience pilot"
  project_id                = var.timeweb_project_id
  os_id                     = data.twc_os.ubuntu.id
  availability_zone         = "fra-1"
  ssh_keys_ids              = [twc_ssh_key.pilot.id]
  is_root_password_required = false
  cloud_init                = templatefile("${path.module}/cloud-init.yaml.tftpl", { admin_cidr = var.admin_cidr })

  configuration {
    configurator_id = data.twc_configurator.frankfurt.id
    cpu             = var.cpu
    ram             = var.ram_mb
    disk            = var.disk_mb
  }

  lifecycle {
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
}
