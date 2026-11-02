"""Operator-only connectivity check; does not expose inventory through Flask."""
import argparse
from dataclasses import asdict
import getpass
import json
import os

from custos.providers.vcenter import VCenterClient, VCenterConfig, VCenterError


def main():
    parser = argparse.ArgumentParser(description="Read-only vCenter inventory check")
    parser.add_argument("command", choices=["vcenter-check"])
    args = parser.parse_args()
    try:
        url = os.environ.get("CUSTOS_VCENTER_URL", "")
        username = os.environ.get("CUSTOS_VCENTER_USERNAME", "")
        if not url or not username:
            raise ValueError("Set CUSTOS_VCENTER_URL and CUSTOS_VCENTER_USERNAME first")
        password = os.environ.get("CUSTOS_VCENTER_PASSWORD") or getpass.getpass("vCenter password: ")
        config = VCenterConfig(url, username, password,
                               ca_bundle=os.environ.get("CUSTOS_VCENTER_CA_BUNDLE"))
        with VCenterClient(config) as client:
            vms = client.list_vms()
        print(json.dumps({"virtual_machines": [asdict(vm) for vm in vms]}, indent=2))
        return 0
    except (ValueError, VCenterError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
