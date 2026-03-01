{
  description = "Carapace Development Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["rust-src" "rust-analyzer" "clippy" "rustfmt"];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            openssl
            just
            cargo-nextest
            cargo-watch
            cargo-tarpaulin
            git
            # Dependencies for common crates
            dbus
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          shellHook = ''
            echo "Welcome to Carapace Dev Environment"
            echo "Rust version: $(rustc --version)"
            export GCLOUD_PROJECT_ID="oisin-488823"
            export GOOGLE_CLOUD_PROJECT="oisin-488823"
            export CLOUDSDK_CORE_PROJECT="oisin-488823"
          '';
        };
      }
    );
}
