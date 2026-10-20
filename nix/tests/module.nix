# The NixOS module with every Linux input on a VM with an AHCI SATA disk, an
# NVMe controller (QEMU emulates SMART for both) and a ZFS pool. Checks that
# the service collects without errors under its sandbox and compares a few
# values with df, zpool and smartctl.
{ self, pkgs }:
pkgs.testers.runNixOSTest {
  name = "calipers";
  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.default ];
      boot.supportedFilesystems.zfs = true;
      networking.hostId = "c0ffee00";
      environment.systemPackages = [ pkgs.smartmontools ];
      users.users.alice.isNormalUser = true;
      virtualisation.qemu.options = [
        "-device ahci,id=ahci0"
        "-blockdev node-name=sata0,driver=null-co,size=1073741824,read-zeroes=on"
        "-device ide-hd,drive=sata0,bus=ahci0.0,model=CALIPERS-SATA,serial=SATA0001"
        "-blockdev node-name=nvm0,driver=null-co,size=1073741824,read-zeroes=on"
        "-device nvme,serial=deadbeef,drive=nvm0"
      ];
      services.calipers = {
        enable = true;
        settings = {
          agent.interval = "1s";
          exporter.listen = "127.0.0.1:9273";
          inputs = {
            cpu = { };
            mem = { };
            swap = { };
            system = { };
            kernel = { };
            disk = { };
            diskio = { };
            net = { };
            netstat = { };
            processes = { };
            procstat = [
              {
                exe = "^sleep$";
                tag_with = [ "pid" ];
              }
            ];
            zfs = { };
            smart = { };
            internal = { };
          };
        };
      };
    };

  testScript = ''
    import json, re

    def scrape():
        out = {}
        text = machine.succeed("curl -sf http://127.0.0.1:9273/metrics")
        for line in text.splitlines():
            m = re.match(r'^(\w+)(?:\{(.*)\})? (\S+)$', line)
            if m:
                labels = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', m.group(2) or ""))
                out.setdefault(m.group(1), []).append((labels, float(m.group(3))))
        return out

    def get(metrics, name, **want):
        hits = [v for labels, v in metrics.get(name, []) if all(labels.get(k) == w for k, w in want.items())]
        assert len(hits) == 1, f"{name} {want}: {hits}"
        return hits[0]

    machine.wait_for_unit("multi-user.target")
    machine.succeed("truncate -s 256M /var/tank.img && zpool create tank /var/tank.img")
    machine.succeed("su alice -c 'sleep 1000 >/dev/null 2>&1 &'")
    # The pool and the sleep appeared after the start; restart so the first
    # collection sees them.
    machine.succeed("systemctl restart calipers.service")
    machine.wait_for_open_port(9273)
    machine.sleep(5)

    m = scrape()
    with subtest("every input collects without errors"):
        errors = {l["collector"]: v for l, v in m["calipers_collector_errors_total"]}
        print(errors)
        assert len(errors) == 13 and not any(errors.values()), errors
        machine.fail("journalctl -u calipers.service | grep 'collection failed'")

    with subtest("disk sees the host's mounts"):
        size, avail = machine.succeed("df -B1 --output=size,avail / | tail -1").split()
        assert get(m, "disk_total_bytes", path="/", mode="rw") == float(size)

    with subtest("procstat reads other users' processes"):
        pid = machine.succeed("pgrep -u alice -x sleep").strip()
        assert get(m, "procstat_open_fds", pid=pid) == 3.0
        assert get(m, "procstat_memory_rss_bytes", pid=pid) > 0

    with subtest("zfs matches zpool"):
        size = machine.succeed("zpool list -Hp -o size tank").strip()
        assert get(m, "zfs_pool_size_bytes", pool="tank") == float(size)
        assert get(m, "zfs_pool_health", pool="tank", state="ONLINE") == 1.0

    with subtest("smart matches smartctl"):
        sata = json.loads(machine.succeed("smartctl -a -j /dev/sda || true"))
        nvme = json.loads(machine.succeed("smartctl -a -j /dev/nvme0 || true"))
        for dev, info in [("sda", sata), ("nvme0", nvme)]:
            assert get(m, "smart_device_healthy", device=dev) == float(info["smart_status"]["passed"])
            assert get(m, "smart_temperature_celsius", device=dev) == float(info["temperature"]["current"])
            assert get(m, "smart_power_cycles", device=dev) == float(info["power_cycle_count"])
        for a in sata["ata_smart_attributes"]["table"]:
            assert get(m, "smart_attribute_raw", device="sda", id=str(a["id"])) == float(a["raw"]["value"])

    with subtest("reload"):
        machine.succeed("systemctl reload calipers.service")
        machine.wait_until_succeeds("journalctl -u calipers.service | grep -q 'configuration reloaded'")
        machine.succeed("systemctl is-active calipers.service")
  '';
}
