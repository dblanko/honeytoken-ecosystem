############################################
# 1. App Registration + Service Principal
#    with ZERO role assignments
############################################
# This is the Azure equivalent of the AWS module's zero-permission
# IAM user. The client_id + client_secret pair together are the
# honeytoken -- scatter them the same way you'd scatter an AWS key.
#
# Unlike AWS IAM (implicit deny + you can still add an explicit deny
# as a belt-and-suspenders move), Azure RBAC is allow-list only: a
# principal with no role assignments already has zero permissions on
# anything. There's no "explicit deny" resource to add here -- simply
# not creating any azurerm_role_assignment for this service principal
# IS the zero-permissions state. Don't add one later by accident.

resource "azuread_application" "canary" {
  display_name = var.canary_app_display_name
}

resource "azuread_application_password" "canary" {
  application_id = azuread_application.canary.id
  display_name   = "honeytoken-secret"
  # No end_date set -- defaults to the provider's standard expiry.
  # A honeytoken secret expiring and quietly stopping to "exist" is
  # arguably fine (an expired credential still shows up in auth logs
  # as a failed attempt when someone tries to use it), but if you'd
  # rather it never expires, set end_date_relative explicitly here.
}

resource "azuread_service_principal" "canary" {
  client_id = azuread_application.canary.client_id
}

############################################
# 2. Resource group for the Event Grid
#    system topic
############################################

resource "azurerm_resource_group" "honeytoken" {
  name     = var.resource_group_name
  location = var.azure_location
}

############################################
# 3. Event Grid System Topic on Activity Log
############################################
# Azure Activity Log is subscription-level and enabled by default --
# there's no equivalent of "you must create a Trail first" like AWS.
# The system topic just exposes those already-flowing events to Event
# Grid so we can subscribe a webhook to them.

resource "azurerm_eventgrid_system_topic" "activity_log" {
  name                   = "honeytoken-activity-log-topic"
  resource_group_name    = azurerm_resource_group.honeytoken.name
  location               = "Global"
  source_arm_resource_id = data.azurerm_subscription.current.id
  topic_type             = "Microsoft.Resources.Subscriptions"
}

############################################
# 4. Event subscription -> straight to the
#    Cloudflare Worker, no function app needed
############################################
# IMPORTANT / UNVERIFIED: the advanced_filter below assumes Activity
# Log events expose the calling service principal's client ID at
# `data.claims.appid`. This matches Microsoft's documented Activity
# Log event schema, but it has not been confirmed against a live
# subscription the way the AWS module's event pattern was (that one
# got fixed twice after real testing surfaced problems -- see the
# main README's "AWS gotchas" section). Treat this filter as a
# starting point, not a guarantee.
#
# If events aren't reaching the Worker after you've confirmed the
# honeytoken credential was actually used (az group list with the
# leaked client_id/secret, or similar), the first thing to check is
# whether this filter is silently excluding everything -- temporarily
# remove the advanced_filter block, redeploy, and see if events show
# up unfiltered. If they do, the field path needs adjusting to match
# what's actually being delivered.

resource "azurerm_eventgrid_system_topic_event_subscription" "to_worker" {
  name                = "honeytoken-to-worker"
  system_topic        = azurerm_eventgrid_system_topic.activity_log.name
  resource_group_name = azurerm_resource_group.honeytoken.name

  included_event_types = [
    "Microsoft.Resources.ResourceWriteFailure",
    "Microsoft.Resources.ResourceWriteSuccess",
    "Microsoft.Resources.ResourceActionFailure",
    "Microsoft.Resources.ResourceActionSuccess",
  ]

  webhook_endpoint {
    url = var.worker_alert_url
  }

  advanced_filter {
    string_contains {
      key    = "data.claims.appid"
      values = [azuread_application.canary.client_id]
    }
  }
}
