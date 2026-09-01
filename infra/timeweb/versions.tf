terraform {
  required_version = ">= 1.8.0"

  required_providers {
    twc = {
      source  = "tf.timeweb.cloud/timeweb-cloud/timeweb-cloud"
      version = "= 1.8.2"
    }
  }
}

provider "twc" {}
