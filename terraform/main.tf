provider "vault" {
  address = "http://localhost:8200"
  token   = "s.m0I588ZImZS0XyEw79eF7xS7"
}

data "vault_generic_secret" "gcp_token" {
  path = "gcp/token/my-token-roleset"
}

provider "google" {
  access_token = data.vault_generic_secret.gcp_token.data["token"]
}

data "google_project" "project" {
  project_id = "fabled-ray-104117"
}

output "project_number" {
  value = data.google_project.project.number
}