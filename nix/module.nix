self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.calipers;
  settingsFormat = pkgs.formats.toml { };
  configFile =
    if cfg.configFile != null then
      cfg.configFile
    else
      settingsFormat.generate "calipers.toml" cfg.settings;
  calipers = lib.getExe cfg.package;
in
{
  options.services.calipers = {
    enable = lib.mkEnableOption "calipers, a system metrics agent with a Prometheus endpoint";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.calipers;
      defaultText = lib.literalExpression "calipe-rs.packages.\${system}.calipers";
      description = "The calipers package to use.";
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          agent.interval = "10s";
          exporter.listen = "0.0.0.0:9273";
          inputs = {
            internal = { };
            http_response = [ { urls = [ "https://example.org" ]; } ];
          };
        }
      '';
      description = ''
        calipers configuration, rendered to TOML. See `resources/calipers.toml`
        in the calipe-rs repository. On Linux only the `internal`,
        `http_response`, `dns_query` and `chrony` inputs are available; the
        others are FreeBSD-only and fail the config check. Ignored when
        {option}`configFile` is set.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to a calipers TOML configuration file; overrides {option}`settings`.";
    };

    extraFlags = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra command line flags for calipers.";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "calipers=debug";
      description = "Value of `RUST_LOG`.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the TCP port of `exporter.listen` (default 9273) in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [
      (
        let
          listen = cfg.settings.exporter.listen or "0.0.0.0:9273";
        in
        lib.toInt (lib.last (lib.splitString ":" listen))
      )
    ];

    systemd.services.calipers = {
      description = "calipers system metrics agent";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      # Reload sends SIGHUP; calipers rereads the file the unit points at, so
      # a changed config needs a restart to pick up the new store path.
      restartTriggers = [ configFile ];
      environment.RUST_LOG = cfg.logLevel;
      serviceConfig = {
        ExecStartPre = "${calipers} --config ${configFile} --check-config";
        ExecStart = lib.escapeShellArgs (
          [
            calipers
            "--config"
            "${configFile}"
          ]
          ++ cfg.extraFlags
        );
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "always";
        RestartSec = 5;

        DynamicUser = true;
        CapabilityBoundingSet = "";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
          "AF_NETLINK"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
