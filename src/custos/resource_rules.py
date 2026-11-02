"""Validated dynamic group rules, bounded regex and IPv4/IPv6 matching."""
from ipaddress import ip_address, ip_network
import regex


def validate_rule(rule):
    if not isinstance(rule, dict) or not rule or set(rule) - {"remote_system_id", "tags", "name_regex", "ip_range", "subnet"}:
        raise ValueError("Specify at least one supported rule")
    if "remote_system_id" in rule and (not isinstance(rule["remote_system_id"], str) or not rule["remote_system_id"]):
        raise ValueError("Backend ID must be a non-empty string")
    if "tags" in rule:
        tags = rule["tags"]
        if not isinstance(tags, dict) or not tags or any(not isinstance(k, str) or not isinstance(v, str) for k,v in tags.items()):
            raise ValueError("Tags must be non-empty string key/value pairs")
    if "name_regex" in rule:
        pattern = rule["name_regex"]
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= 256:
            raise ValueError("VM-name regex must contain 1 to 256 characters")
        try:
            regex.compile(pattern)
        except regex.error:
            raise ValueError("Invalid VM-name regex") from None
    if "subnet" in rule:
        if not isinstance(rule["subnet"], str):
            raise ValueError("Subnet must be CIDR text")
        ip_network(rule["subnet"], strict=True)
    if "ip_range" in rule:
        value = rule["ip_range"]
        if not isinstance(value, dict) or set(value) != {"start", "end"} or any(not isinstance(v, str) for v in value.values()):
            raise ValueError("IP range requires start and end addresses")
        start, end = ip_address(value["start"]), ip_address(value["end"])
        if start.version != end.version or int(start) > int(end):
            raise ValueError("IP range endpoints must use the same IP family and ascending order")
    return rule


def matches(rule, vm, addresses=()):
    try:
        validate_rule(rule)
        if "remote_system_id" in rule and rule["remote_system_id"] != vm.remote_system_id:
            return False
        if "tags" in rule and any((vm.tags or {}).get(k) != v for k,v in rule["tags"].items()):
            return False
        if "name_regex" in rule and not regex.search(rule["name_regex"], vm.inventory_name[:1024], timeout=0.02):
            return False
        if "subnet" in rule or "ip_range" in rule:
            ips = []
            for address in set(addresses) | ({vm.primary_ip} if vm.primary_ip else set()):
                try:
                    ips.append(ip_address(address))
                except ValueError:
                    pass
            network = ip_network(rule["subnet"]) if "subnet" in rule else None
            start, end = (ip_address(rule["ip_range"][k]) for k in ("start", "end")) if "ip_range" in rule else (None, None)
            # A single discovered IP must satisfy all specified IP constraints.
            if not any((network is None or ip in network) and
                       (start is None or (ip.version == start.version and int(start) <= int(ip) <= int(end))) for ip in ips):
                return False
        return True
    except (ValueError, TypeError, AttributeError, TimeoutError, regex.error):
        return False
