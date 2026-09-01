variable "project_name" {
  description = "Stable label used for the pilot resources."
  type        = string
  default     = "acvpn-frankfurt-pilot"
}

variable "timeweb_project_id" {
  description = "Existing Timeweb project ID. Reusing a project keeps the API token project-scoped."
  type        = number

  validation {
    condition     = var.timeweb_project_id > 0 && floor(var.timeweb_project_id) == var.timeweb_project_id
    error_message = "timeweb_project_id must be a positive integer."
  }
}

variable "server_name" {
  description = "Pilot server name and hostname."
  type        = string
  default     = "acvpn-fra-pilot-1"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,62}$", var.server_name))
    error_message = "server_name must be a canonical DNS label."
  }
}

variable "ssh_public_key_path" {
  description = "Absolute path to a dedicated Ed25519 public key."
  type        = string

  validation {
    condition     = trimspace(var.ssh_public_key_path) != ""
    error_message = "ssh_public_key_path must not be empty."
  }
}

variable "awg_port" {
  description = "UDP port selected in official AmneziaVPN after listener inventory."
  type        = number
  default     = 585

  validation {
    condition     = floor(var.awg_port) == var.awg_port && var.awg_port >= 1 && var.awg_port <= 65535 && var.awg_port != 22
    error_message = "awg_port must be a valid non-SSH UDP port."
  }
}

variable "reality_port" {
  description = "TCP port selected for XRay Reality after listener inventory."
  type        = number
  default     = 443

  validation {
    condition     = floor(var.reality_port) == var.reality_port && var.reality_port >= 1 && var.reality_port <= 65535 && var.reality_port != 22
    error_message = "reality_port must be a valid non-SSH TCP port."
  }
}

variable "admin_cidr" {
  description = "Single trusted IPv4 administration address as an exact /32."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && can(regex("^[0-9.]+/32$", var.admin_cidr))
    error_message = "admin_cidr must be one valid IPv4 address with a /32 prefix."
  }
}

variable "cpu" {
  type    = number
  default = 2
}

variable "ram_mb" {
  type    = number
  default = 2048
}

variable "disk_mb" {
  type    = number
  default = 20 * 1024
}
