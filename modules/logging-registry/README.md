# Logging Registry Module

Selects a logging bucket name from a JSON registry based on AWS account and region.

## Registry formats supported

Nested format:
```json
{
  "111122223333": {
    "us-east-1": "central-logs-use1",
    "*": "central-logs-default"
  },
  "*": {
    "eu-west-1": "eu-logs",
    "*": "global-logs"
  }
}
```

Flat format:
```json
{
  "111122223333:us-east-1": "central-logs-use1",
  "111122223333:*": "acct-default-logs",
  "*:eu-west-1": "eu-logs",
  "*:*": "global-logs"
}
```

## Inputs

- `registry_path` – path to JSON file
- `account_id` – optional override (defaults from AWS caller identity)
- `region` – optional override (defaults from AWS provider region)

## Output

- `bucket_name` – the selected logging bucket
