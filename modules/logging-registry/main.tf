data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  registry   = jsondecode(file(var.registry_path))
  account_id = var.account_id != null ? var.account_id : data.aws_caller_identity.current.account_id
  region     = var.region != null ? var.region : data.aws_region.current.id

  # Registry format options supported:
  # 1) { "<account_id>": { "<region>": "bucket-name", "*": "bucket-name" }, "*": { "us-east-1": "bucket", "*": "bucket" } }
  # 2) Flat map keyed by "<account_id>:<region>" or "*:<region>" or "<account_id>:*" or "*:*"

  # Lookups in order of specificity
  key_account_region = "${local.account_id}:${local.region}"
  key_account_any    = "${local.account_id}:*"
  key_any_region     = "*:${local.region}"
  key_any_any        = "*:*"

  flat = can(local.registry[local.key_account_region]) || can(local.registry[local.key_any_region]) || can(local.registry[local.key_account_any]) || can(local.registry[local.key_any_any])

  from_flat = local.flat ? coalesce(
    try(local.registry[local.key_account_region], null),
    try(local.registry[local.key_any_region], null),
    try(local.registry[local.key_account_any], null),
    try(local.registry[local.key_any_any], null)
  ) : null

  from_nested = !local.flat ? coalesce(
    try(local.registry[local.account_id][local.region], null),
    try(local.registry[local.account_id]["*"], null),
    try(local.registry["*"][local.region], null),
    try(local.registry["*"]["*"], null)
  ) : null

  selected_bucket = coalesce(local.from_flat, local.from_nested)
}

# Fail clearly if no bucket could be selected
locals {
  _validate = local.selected_bucket != null ? true : tobool("No logging bucket found in registry for account " + local.account_id + " and region " + local.region)
}

output "bucket_name" {
  description = "Selected logging bucket name from registry"
  value       = local.selected_bucket
}
