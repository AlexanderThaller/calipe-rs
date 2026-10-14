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
            cpu = { };
            mem = { };
            disk.ignore_fs = [ "tmpfs" "devtmpfs" ];
            internal = { };
            http_response = [ { urls = [ "https://example.org" ]; } ];
          };
        }
      '';
      description = ''
        calipers configuration, rendered to TOML. See `resources/calipers.toml`
        in the calipe-rs repository. Every input except `pf` is available on
        Linux. Ignored when {option}`configFile` is set.
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

    capabilities = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        # procstat: /proc/<pid>/{io,fd} of other users' processes.
        "CAP_SYS_PTRACE"
        "CAP_DAC_READ_SEARCH"
      ]
      ++ lib.optionals (cfg.settings ? inputs.smart) [
        # SG_IO ATA pass-through and NVMe admin commands.
        "CAP_SYS_RAWIO"
        "CAP_SYS_ADMIN"
      ];
      defaultText = lib.literalMD ''
        `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, plus `CAP_SYS_RAWIO` and
        `CAP_SYS_ADMIN` when {option}`settings` enables the smart input
      '';
      description = ''
        Capabilities calipers keeps; it runs as root with only these. Add
        `CAP_SYS_RAWIO` and `CAP_SYS_ADMIN` for the smart input when using
        {option}`configFile`.
      '';
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

        # Root with a reduced capability set instead of DynamicUser: the disk
        # input needs the host's mount table, so no option may give the unit
        # its own mount namespace (ProtectSystem, PrivateTmp, PrivateDevices,
        # ProtectKernel*, ...), and smart and zfs need the device nodes.
        CapabilityBoundingSet = cfg.capabilities;
        NoNewPrivileges = true;
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
