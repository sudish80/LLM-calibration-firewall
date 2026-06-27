provider "docker" {}

resource "docker_image" "firewall" {
  name         = "llmfirewall:latest"
  build {
    path       = "../.."
    dockerfile = "Dockerfile"
  }
}

resource "docker_container" "firewall" {
  name  = "llmfirewall"
  image = docker_image.firewall.image_id
  ports {
    internal = 8000
    external = 8000
  }
  volumes {
    container_path = "/data"
    volume_name    = docker_volume.firewall_data.name
  }
  env = [
    "LLMFW_TOXICITY_THRESHOLD=0.5",
    "LLMFW_SEMANTIC_THRESHOLD=0.8",
    "LLMFW_DEVICE=cpu",
    "LLMFW_SERVER_WORKERS=2",
  ]
}

resource "docker_volume" "firewall_data" {
  name = "firewall_data"
}
