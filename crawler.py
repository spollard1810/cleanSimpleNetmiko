from Core import NetworkDevice
import argparse
import csv
import getpass
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

CDP_DETAIL_COMMAND = "show cdp n det"

# Simple CDP-based device type detection map (substring -> Netmiko device_type).
DEVICE_TYPE_DETECTION_MAP = {
    "ios xr": "cisco_xr",
    "nx-os": "cisco_nxos",
    "nexus": "cisco_nxos",
    "adaptive security appliance": "cisco_asa",
    " asa ": "cisco_asa",
    "wireless lan controller": "cisco_wlc",
    "wireless": "cisco_wlc",
    "wlc": "cisco_wlc",
    "catalyst": "cisco_ios",
    "ios": "cisco_ios",
}


def load_csv_devices(filename, username, password, session_log):
    """Load seed devices from CSV with hostname and deviceType/device_type columns."""
    devices = []
    with open(filename, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            hostname = (row.get("hostname") or "").strip()
            device_type = (row.get("deviceType") or row.get("device_type") or "").strip()
            if not hostname or not device_type:
                continue
            devices.append(
                NetworkDevice(
                    hostname,
                    device_type,
                    username,
                    password,
                    session_log=session_log,
                )
            )
    return devices


def detect_device_type(platform, capabilities, device_id):
    """Infer Netmiko device_type from CDP neighbor attributes."""
    blob = f" {platform or ''} {capabilities or ''} {device_id or ''} ".lower()
    for marker, device_type in DEVICE_TYPE_DETECTION_MAP.items():
        if marker in blob:
            return device_type
    return "cisco_ios"


def normalize_cdp_neighbors(parsed):
    """Normalize NTC-Templates CDP parsed output to list[dict]."""
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def neighbor_value(neighbor, keys):
    """Return first non-empty value from a list of possible CDP keys."""
    for key in keys:
        value = neighbor.get(key)
        if value:
            return str(value).strip()
    return ""


def neighbor_to_device_data(neighbor):
    """Extract canonical fields from one CDP neighbor record."""
    mgmt_ip = neighbor_value(neighbor, ["management_ip", "mgmt_ip", "ip_address", "entry_address"])
    device_id = neighbor_value(neighbor, ["device_id", "destination_host", "neighbor"])
    platform = neighbor_value(neighbor, ["platform"])
    capabilities = neighbor_value(neighbor, ["capabilities", "capability"])
    hostname = mgmt_ip or device_id
    if not hostname:
        return None

    return {
        "hostname": hostname,
        "mgmt_ip": mgmt_ip,
        "device_id": device_id,
        "platform": platform,
        "capabilities": capabilities,
        "device_type": detect_device_type(platform, capabilities, device_id),
    }


def device_identity(hostname, device_type):
    """Stable device identity key."""
    return f"{(hostname or '').strip().lower()}|{(device_type or '').strip().lower()}"


def track_seen_device(
    seen_devices,
    hostname,
    device_type,
    platform="",
    capabilities="",
    seen_via="",
    discovered=False,
):
    """Track every device seen (seed + CDP neighbors), not only crawled."""
    key = device_identity(hostname, device_type)
    if key not in seen_devices:
        seen_devices[key] = {
            "hostname": hostname,
            "device_type": device_type,
            "platform": platform,
            "capabilities": capabilities,
            "discovered": discovered,
            "seen_via": [],
        }

    current = seen_devices[key]
    if platform and not current["platform"]:
        current["platform"] = platform
    if capabilities and not current["capabilities"]:
        current["capabilities"] = capabilities
    current["discovered"] = current["discovered"] or discovered
    if seen_via and seen_via not in current["seen_via"]:
        current["seen_via"].append(seen_via)

    return key


def build_device_from_neighbor(neighbor, username, password, session_log):
    """Create a NetworkDevice from one CDP neighbor record."""
    data = neighbor_to_device_data(neighbor)
    if not data:
        return None, None

    device = NetworkDevice(
        data["hostname"],
        data["device_type"],
        username,
        password,
        session_log=session_log,
    )
    return device, data


def crawl(device):
    """Main crawl action for one device: run CDP detail and parse via NTC templates."""
    result = {
        "hostname": device.hostname,
        "device_type": device.device_type,
        "cdp_neighbors": [],
        "error": None,
    }

    try:
        device.connect()
        parsed = device.sendCommand(CDP_DETAIL_COMMAND, use_textfsm=True)
        result["cdp_neighbors"] = normalize_cdp_neighbors(parsed)
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        device.disconnect()

    return result


def worker(device):
    """Thread worker wrapper that invokes crawl()."""
    return crawl(device)


def crawl_recursive(
    queue_devices,
    username,
    password,
    allow_types,
    max_depth,
    max_workers,
    seen_devices,
    crawled_devices,
    discovered_devices,
    session_log,
    depth=0,
):
    """
    Crawl one queue level fully, collect discovered devices in a list,
    then recurse by setting that discovered list as the next queue.
    """
    if not queue_devices or depth >= max_depth:
        return []

    current_batch = []
    for device in queue_devices:
        track_seen_device(
            seen_devices,
            hostname=device.hostname,
            device_type=device.device_type,
            seen_via="seed" if depth == 0 else "",
            discovered=(depth != 0),
        )
        key = device_identity(device.hostname, device.device_type)
        if key in crawled_devices:
            continue
        crawled_devices.add(key)
        current_batch.append(device)

    if not current_batch:
        return []

    logging.info("Depth=%s queue=%s", depth, len(current_batch))
    results = []
    worker_count = max(1, min(max_workers, len(current_batch)))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(worker, device) for device in current_batch]
        for future in as_completed(futures):
            results.append(future.result())

    discovered_queue = []
    discovered_queue_keys = set()

    for result in results:
        source_hostname = result["hostname"]
        for neighbor in result.get("cdp_neighbors", []):
            next_device, device_data = build_device_from_neighbor(
                neighbor,
                username,
                password,
                session_log=session_log,
            )
            if not next_device or not device_data:
                continue

            device_key = device_identity(next_device.hostname, next_device.device_type)
            track_seen_device(
                seen_devices,
                hostname=next_device.hostname,
                device_type=next_device.device_type,
                platform=device_data["platform"],
                capabilities=device_data["capabilities"],
                seen_via=source_hostname,
                discovered=True,
            )

            if allow_types and next_device.device_type not in allow_types:
                logging.info(
                    "Skipping unsupported type host=%s type=%s platform=%s",
                    next_device.hostname,
                    next_device.device_type,
                    device_data["platform"],
                )
                continue
            if device_key in crawled_devices or device_key in discovered_queue_keys:
                continue

            discovered_queue_keys.add(device_key)
            if device_key not in discovered_devices:
                discovered_devices[device_key] = {
                    "hostname": next_device.hostname,
                    "device_type": next_device.device_type,
                    "platform": device_data["platform"],
                    "capabilities": device_data["capabilities"],
                    "discovered_from": source_hostname,
                }
            discovered_queue.append(next_device)

    return results + crawl_recursive(
        discovered_queue,
        username,
        password,
        allow_types,
        max_depth,
        max_workers,
        seen_devices,
        crawled_devices,
        discovered_devices,
        session_log,
        depth=depth + 1,
    )


def crawl_network(seed_devices, username, password, allow_types, max_depth=3, max_workers=10, session_log=None):
    """Entry point for recursive threadpool crawler."""
    seen_devices = {}
    crawled_devices = set()
    discovered_devices = {}

    crawled_results = crawl_recursive(
        queue_devices=list(seed_devices),
        username=username,
        password=password,
        allow_types=allow_types,
        max_depth=max_depth,
        max_workers=max_workers,
        seen_devices=seen_devices,
        crawled_devices=crawled_devices,
        discovered_devices=discovered_devices,
        session_log=session_log,
        depth=0,
    )

    return {
        "summary": {
            "seed_count": len(seed_devices),
            "crawled_count": len(crawled_devices),
            "seen_count": len(seen_devices),
            "discovered_count": len(discovered_devices),
            "max_depth": max_depth,
            "cdp_command": CDP_DETAIL_COMMAND,
        },
        "crawled_devices": sorted(crawled_results, key=lambda item: item.get("hostname", "").lower()),
        "seen_devices": sorted(seen_devices.values(), key=lambda item: item.get("hostname", "").lower()),
        "discovered_devices": sorted(discovered_devices.values(), key=lambda item: item.get("hostname", "").lower()),
    }


def save_results(report, output_base):
    """Save crawler report to JSON and CSVs."""
    crawled_results = report.get("crawled_devices", [])
    seen_results = report.get("seen_devices", [])
    discovered_results = report.get("discovered_devices", [])

    json_path = f"{output_base}.json"
    crawled_csv_path = f"{output_base}.csv"
    seen_csv_path = f"{output_base}_seen.csv"
    discovered_csv_path = f"{output_base}_discovered.csv"

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    with open(crawled_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["hostname", "device_type", "status", "error", "neighbor_count"],
        )
        writer.writeheader()
        for item in crawled_results:
            writer.writerow(
                {
                    "hostname": item.get("hostname"),
                    "device_type": item.get("device_type"),
                    "status": "OK" if not item.get("error") else "ERROR",
                    "error": item.get("error"),
                    "neighbor_count": len(item.get("cdp_neighbors") or []),
                }
            )

    with open(seen_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["hostname", "device_type", "platform", "capabilities", "discovered", "seen_via"],
        )
        writer.writeheader()
        for item in seen_results:
            writer.writerow(
                {
                    "hostname": item.get("hostname"),
                    "device_type": item.get("device_type"),
                    "platform": item.get("platform"),
                    "capabilities": item.get("capabilities"),
                    "discovered": item.get("discovered"),
                    "seen_via": ",".join(item.get("seen_via") or []),
                }
            )

    with open(discovered_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["hostname", "device_type", "platform", "capabilities", "discovered_from"],
        )
        writer.writeheader()
        writer.writerows(discovered_results)

    print(
        "Saved results: "
        f"{json_path}, {crawled_csv_path}, {seen_csv_path}, {discovered_csv_path}"
    )


def main():
    parser = argparse.ArgumentParser(description="Recursive CDP crawler")
    parser.add_argument("--csv", default="devices.csv", help="Seed device CSV file")
    parser.add_argument("--max-depth", type=int, default=3, help="Max recursive depth")
    parser.add_argument("--max-workers", type=int, default=10, help="Thread pool size")
    parser.add_argument("--output", default="crawl_results", help="Output base filename")
    parser.add_argument(
        "--allow-types",
        default="cisco_ios,cisco_nxos,cisco_xr,cisco_asa,cisco_wlc",
        help="Comma-separated Netmiko device_type allowlist (empty = allow all)",
    )
    parser.add_argument(
        "--log-file",
        default="crawler.log",
        help="Combined script and Netmiko session log file",
    )
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    seed_devices = load_csv_devices(args.csv, username, password, session_log=args.log_file)
    if not seed_devices:
        print("No valid devices found in CSV.")
        return

    allow_types = {item.strip() for item in args.allow_types.split(",") if item.strip()}
    if allow_types:
        logging.info("Allowlist types: %s", ",".join(sorted(allow_types)))
    else:
        logging.info("Allowlist types: all")

    report = crawl_network(
        seed_devices=seed_devices,
        username=username,
        password=password,
        allow_types=allow_types,
        max_depth=max(1, args.max_depth),
        max_workers=max(1, args.max_workers),
        session_log=args.log_file,
    )

    summary = report["summary"]
    print(f"\nCrawled devices: {summary['crawled_count']}")
    print(f"Seen devices: {summary['seen_count']}")
    print(f"Discovered devices: {summary['discovered_count']}")
    print(f"CDP command: {summary['cdp_command']}")

    for item in report["crawled_devices"]:
        status = "OK" if not item.get("error") else f"ERROR: {item.get('error')}"
        print(f"- {item.get('hostname')} ({item.get('device_type')}): {status}")

    save_results(report, args.output)


if __name__ == "__main__":
    main()
