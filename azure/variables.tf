variable "azure_location" {
  description = "Azure region for the resource group hosting the Event Grid system topic. The honeytoken identity itself (App Registration / Service Principal) is tenant-wide and not tied to a region."
  type        = string
  default     = "westeurope"
}

variable "resource_group_name" {
  description = "Name of the resource group created to hold the Event Grid system topic. A dedicated, obviously-named group keeps this easy to find and tear down later."
  type        = string
  default     = "honeytoken-canary-rg"
}

variable "canary_app_display_name" {
  description = "Display name of the honeytoken App Registration. Make it sound like a real internal service account, same idea as the AWS module's canary_user_name."
  type        = string
  default     = "svc-legacy-reporting"
}

variable "worker_alert_url" {
  description = <<-EOT
    Full URL of your Cloudflare Worker's Azure endpoint, e.g.
    https://canary.example.com/azure-hit/<canary_id>

    Note the different path prefix from the AWS module: /azure-hit/
    not /hit/. The Worker needs the Azure-specific handler to deal
    with the Event Grid validation handshake -- pointing this at a
    plain /hit/ path will fail subscription validation.
  EOT
  type = string
}
