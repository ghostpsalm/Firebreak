output "public_ip" {
  description = "Point your A record here; certbot picks it up within ten minutes."
  value       = oci_core_instance.this.public_ip
}

output "endpoint" {
  description = "Set this as ENDPOINT in src/telemetry.rs, then cut a build."
  value       = "https://${var.domain_name}/v1/ping"
}

output "ssh" {
  description = "How to get onto the box."
  value       = "ssh ubuntu@${oci_core_instance.this.public_ip}"
}

output "next_steps" {
  description = "What to do once apply finishes."
  value       = <<-EOT

    1. DNS      A record: ${var.domain_name} -> ${oci_core_instance.this.public_ip}
                A timer retries every 10 minutes, so this can be done after apply.

    2. Verify   curl https://${var.domain_name}/healthz          (expect: ok)
                ssh ubuntu@${oci_core_instance.this.public_ip} \
                  'sudo journalctl -u firebreak-receiver -f'

    3. Client   set ENDPOINT in src/telemetry.rs to
                  https://${var.domain_name}/v1/ping
                and cut a release. Until then no build sends anything, and
                no consent prompt is shown.

    4. Look     ssh ubuntu@${oci_core_instance.this.public_ip} \
                  'sudo firebreak-telemetry-summary'

    5. Back up  scp ubuntu@${oci_core_instance.this.public_ip}:/var/lib/firebreak-receiver/telemetry.db .
                (needs sudo on the box; see server/README.md)
  EOT
}
