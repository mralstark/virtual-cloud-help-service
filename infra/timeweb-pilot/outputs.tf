output "server_id" {
  value = twc_server.pilot.id
}

output "server_ipv4" {
  value = twc_server.pilot.main_ipv4
}

output "deployment_warning" {
  value = "This single-provider pilot does not bypass a strict allowlist unless its destination is explicitly approved."
}
