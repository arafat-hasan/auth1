# Example placeholders

Empty files named by `config.example.yaml`, so that `auth1 config check --config
config.example.yaml` passes from the repository root. They hold no keys: `config check` only
checks that each file exists and is readable. Real fixtures replace them when the packages that
parse keyrings and keys arrive (WP-10, WP-12). Never put real secrets here.
