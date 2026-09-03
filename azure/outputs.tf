output "canary_client_id" {
  description = "The App (client) ID of the honeytoken. This is the 'username' half of the credential pair -- goes in decoy files alongside the secret."
  value       = azuread_application.canary.client_id
}

output "canary_client_secret" {
  description = "The client secret of the honeytoken. This is the actual bait -- treat it exactly like the AWS module's canary_secret_access_key."
  value       = azuread_application_password.canary.value
  sensitive   = true
}

output "canary_tenant_id" {
  description = "Azure AD tenant ID -- needed alongside client_id/client_secret for anyone (including a simulated attacker) to actually authenticate with this honeytoken."
  value       = data.azuread_client_config.current.tenant_id
}

output "canary_service_principal_object_id" {
  description = "Object ID of the honeytoken's service principal, useful for confirming in the Azure Portal that no role assignments exist."
  value       = azuread_service_principal.canary.object_id
}

output "event_subscription_name" {
  description = "Name of the Event Grid subscription watching for this honeytoken's use."
  value       = azurerm_eventgrid_system_topic_event_subscription.to_worker.name
}
