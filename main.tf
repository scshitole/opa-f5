terraform {
  cloud {
    organization = "f5networks-bd"

    workspaces {
      name = "as3-space"
    }
  }
  required_providers {
    bigip = {
      source  = "F5Networks/bigip"
      version = "1.11.1"
    }
  }
}
provider "bigip" {
  address  = "https://${var.address}:${var.port}"
  username = var.username
  password = var.password
}

# deploy application using as3
resource "bigip_as3" "nginx" {
  as3_json = file(var.declaration)
}
