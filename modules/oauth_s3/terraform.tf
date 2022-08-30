terraform {
  required_version = ">= 1.1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.18"
    }

    random = {
      source  = "hashicorp/random"
      version = ">= 2.2.0"
    }
  }
}
