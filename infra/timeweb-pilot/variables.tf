variable "project_name" {
  description = "Timeweb project name for the disposable pilot."
  type        = string
  default     = "acvpn-frankfurt-pilot"
}

variable "server_name" {
  description = "Pilot server name and hostname."
  type        = string
  default     = "acvpn-fra-pilot-1"
}

variable "ssh_public_key_path" {
  description = "Absolute path to a dedicated Ed25519 public key."
  type        = string
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
