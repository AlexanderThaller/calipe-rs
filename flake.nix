{
  description = "calipers: lightweight system metrics agent with a Prometheus endpoint";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            }
          )
        );

      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      mkCalipers =
        pkgs:
        let
          toolchain = pkgs.rust-bin.stable.latest.minimal;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
        in
        rustPlatform.buildRustPackage {
          pname = "calipers";
          inherit (cargoToml.package) version;

          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./src
              ./resources/calipers.toml
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          buildType = "deploy";
          nativeBuildInputs = [ pkgs.protobuf ];
          # The http_response tests build a client, which loads the system trust store.
          nativeCheckInputs = [ pkgs.cacert ];

          meta = {
            description = "Lightweight system metrics agent with a Prometheus endpoint";
            mainProgram = "calipers";
            platforms = pkgs.lib.platforms.linux ++ pkgs.lib.platforms.freebsd;
          };
        };
    in
    {
      overlays.default = final: _prev: {
        calipers = mkCalipers (final.extend rust-overlay.overlays.default);
      };

      packages = forAllSystems (pkgs: rec {
        calipers = mkCalipers pkgs;
        default = calipers;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.rust-bin.stable.latest.default.override {
              extensions = [
                "rust-src"
                "rust-analyzer"
              ];
            })
            pkgs.protobuf
            pkgs.python3
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);

      nixosModules.default = import ./nix/module.nix self;

      checks = forAllSystems (pkgs: {
        inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) calipers;
        nixos-module = pkgs.testers.runNixOSTest {
          name = "calipers";
          nodes.machine = {
            imports = [ self.nixosModules.default ];
            services.calipers = {
              enable = true;
              settings = {
                agent.interval = "1s";
                exporter.listen = "127.0.0.1:9273";
                inputs.internal = { };
              };
            };
          };
          testScript = ''
            machine.wait_for_unit("calipers.service")
            machine.wait_for_open_port(9273)
            machine.wait_until_succeeds("curl -sf http://127.0.0.1:9273/metrics | grep -q '^calipers_'")
            machine.succeed("systemctl reload calipers.service")
            machine.wait_until_succeeds("journalctl -u calipers.service | grep -q 'configuration reloaded'")
            machine.succeed("systemctl is-active calipers.service")
          '';
        };
      });
    };
}
