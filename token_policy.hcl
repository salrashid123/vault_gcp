
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew" {
  capabilities = ["update", "create"]
}

path "auth/token/lookup-accessor" {
  capabilities = [ "read", "update" ]
}

# Allow tokens to renew themselves
path "auth/token/renew-self" {
    capabilities = ["update"]
}

# Allow tokens to revoke themselves
path "auth/token/revoke-self" {
    capabilities = ["update"]
}
