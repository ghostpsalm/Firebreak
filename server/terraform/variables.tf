// ---- OCI authentication ----
// These come from the API key you create under your user in the OCI console
// (Profile -> User settings -> API keys). `oci setup config` writes all five
// into ~/.oci/config if you would rather read them off there.

variable "tenancy_ocid" {
  type        = string
  description = "OCID of the tenancy."
}

variable "user_ocid" {
  type        = string
  description = "OCID of the user the API key belongs to."
}

variable "fingerprint" {
  type        = string
  description = "Fingerprint of the API signing key."
}

variable "private_key_path" {
  type        = string
  description = "Path to the API signing private key (PEM)."
}

variable "region" {
  type        = string
  description = "Region to deploy into, e.g. uk-london-1. Always Free resources live in your home region."
}

variable "compartment_ocid" {
  type        = string
  description = "Compartment to create everything in. The tenancy OCID works if you have not made compartments."
}

// ---- the host ----

variable "name" {
  type        = string
  description = "Name prefix for every resource, so they are obvious in the console."
  default     = "firebreak-collector"
}

variable "instance_shape" {
  type        = string
  description = <<-EOT
    Always Free shapes:
      VM.Standard.E2.1.Micro  AMD, 1 OCPU / 1 GB. Two are free, and capacity
                              is nearly always available. The default.
      VM.Standard.A1.Flex     Ampere ARM, up to 4 OCPU / 24 GB free. Far more
                              machine, but "Out of host capacity" is common
                              in the free tier and you may have to retry.
  EOT
  default     = "VM.Standard.E2.1.Micro"
}

variable "shape_ocpus" {
  type        = number
  description = "OCPUs. Only used by flexible shapes (A1.Flex); ignored otherwise."
  default     = 1
}

variable "shape_memory_gb" {
  type        = number
  description = "Memory in GB. Only used by flexible shapes (A1.Flex); ignored otherwise."
  default     = 6
}

variable "availability_domain_index" {
  type        = number
  description = "Which availability domain to use. Try 1 or 2 if A1.Flex reports no capacity in 0."
  default     = 0
}

variable "boot_volume_gb" {
  type        = number
  description = "Boot volume size. The Always Free storage allowance is 200 GB total across volumes."
  default     = 50
}

// ---- access ----

variable "ssh_public_key" {
  type        = string
  description = "Public key installed for the ubuntu user, e.g. file(\"~/.ssh/id_ed25519.pub\")."
}

variable "ssh_private_key_path" {
  type        = string
  description = "Matching private key. Terraform uses it to copy the receiver up and restart it."
}

variable "ssh_allowed_cidr" {
  type        = string
  description = <<-EOT
    Who may reach port 22. Defaults to the whole internet because a home
    connection rarely has a fixed address, but narrow this to your own /32
    if you can — it is the only port on the box that is worth attacking.
  EOT
  default     = "0.0.0.0/0"
}

// ---- the service ----

variable "domain_name" {
  type        = string
  description = <<-EOT
    Hostname the collector answers on, e.g. telemetry.example.com. Point an A
    record at the IP this stack outputs; certbot gets a certificate on its own
    once that resolves, retrying every ten minutes until it does.
  EOT
}

variable "acme_email" {
  type        = string
  description = "Contact address for Let's Encrypt expiry notices."
}

variable "deno_version" {
  type        = string
  description = <<-EOT
    Deno release the collector runs on, e.g. "v2.8.1". Pinned deliberately:
    an unpinned runtime on a box nobody watches is a surprise waiting for a
    quiet week. Bump it when you have a reason to.
  EOT
  default     = "v2.8.1"
}

variable "retention_days" {
  type        = number
  description = <<-EOT
    How long a ping is kept. A truncated address is still arguably personal
    data, so this is a decision to make rather than leave at "forever".
  EOT
  default     = 400
}

variable "rate_per_hour" {
  type        = number
  description = "Requests accepted per hour per /24 or /48. A single network can hold a lot of machines that all boot at nine."
  default     = 240
}
