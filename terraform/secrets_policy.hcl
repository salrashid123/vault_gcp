
path "auth/approle/role/observatory/secret-id" {
  capabilities = ["read", "create", "update", "list"]
}

path "gcp/token/my-token-roleset" {
    capabilities = ["read"]
}
