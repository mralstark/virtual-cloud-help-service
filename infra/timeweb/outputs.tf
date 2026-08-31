output "server_id" {
  value = twc_server.pilot.id
}

output "server_ipv4" {
  value = twc_server.pilot.main_ipv4
}

output "deployment_warning" {
  value = "Official Amnezia installation, post-install inventory, backup, and acceptance tests remain manual gates."
}
