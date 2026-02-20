{
  description = "CIP-100 body hash signer — signs with Cardano BIP32-Ed25519 key from stdin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forEachSystem (pkgs: {
        default = pkgs.buildNpmPackage {
          pname = "cip100-sign";
          version = "0.1.0";
          src = ./.;
          npmDepsHash = "sha256-3nrXDv6Toki7Az+qpNJ8PxIv7rWj+8xIQ0F2Bewzt7k=";
          dontNpmBuild = true;
          installPhase = ''
            mkdir -p $out/lib/node_modules/cip100-sign $out/bin
            cp -r node_modules $out/lib/node_modules/cip100-sign/
            cp sign.mjs lib.mjs test.mjs $out/lib/node_modules/cip100-sign/
            cp package.json $out/lib/node_modules/cip100-sign/
            cat > $out/bin/cip100-sign <<'WRAPPER'
            #!/bin/sh
            exec ${pkgs.nodejs_20}/bin/node "$(dirname "$(readlink -f "$0")")/../lib/node_modules/cip100-sign/sign.mjs" "$@"
            WRAPPER
            chmod +x $out/bin/cip100-sign
          '';
          doCheck = true;
          checkPhase = ''
            ${pkgs.nodejs_20}/bin/node test.mjs
          '';
        };
      });

      apps = forEachSystem (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.default}/bin/cip100-sign";
        };
      });

      checks = forEachSystem (pkgs: {
        default = self.packages.${pkgs.system}.default;
      });
    };
}
