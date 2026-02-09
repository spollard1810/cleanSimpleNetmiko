from Core import NetworkDevice
import argparse
import csv
import getpass
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


def load_csv_devices(filename, username, password, session_log):
    """Load device list from CSV file with hostname and deviceType headers."""
    devices = []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            hostname = row.get('hostname')
            device_type = row.get('deviceType') or row.get('device_type')
            if not hostname or not device_type:
                continue
            devices.append(NetworkDevice(hostname, device_type, username, password, session_log=session_log))
    return devices


def detect_device_type(platform, capabilities, device_id):
    """Infer Netmiko device_type from CDP neighbor attributes."""
    blob = " ".join([platform or "", capabilities or "", device_id or ""]).lower()

    patterns = [
        (r'cisco nx-os|nexus|\bn[3579]k\b', 'cisco_nxos'),
        (r'adaptive security appliance|\basa\b', 'cisco_asa'),
        (r'wireless|controller|\bwlc\b', 'cisco_wlc'),
        (r'ios xr|\bxr\b', 'cisco_xr'),
        (r'catalyst|\bc\d{3,4}\b|\bws-\b', 'cisco_ios'),
    ]

    for pattern, device_type in patterns:
        if re.search(pattern, blob):
            return device_type

    return 'cisco_ios'


def normalize_cdp_neighbors(parsed):
    """Normalize NTC-Templates CDP output to a list of dicts."""
    if not parsed:
        return []
    if isinstance(parsed, list):
        return [p for p in parsed if isinstance(p, dict)]
    return []


def crawl_device(device):
    """Connect to a device, run show inventory and show cdp neighbors, return parsed data."""
    result = {
        'hostname': device.hostname,
        'device_type': device.device_type,
        'inventory': None,
        'cdp_neighbors': [],
        'error': None,
    }

    try:
        device.connect()
        result['inventory'] = device.sendCommand("show inventory")
        cdp_parsed = device.sendCommand("show cdp neighbors detail", use_textfsm=True)
        result['cdp_neighbors'] = normalize_cdp_neighbors(cdp_parsed)
    except Exception as e:
        result['error'] = str(e)
    finally:
        device.disconnect()

    return result


def build_device_from_neighbor(neighbor, username, password):
    """Create a NetworkDevice from CDP neighbor data."""
    mgmt_ip = neighbor.get('management_ip') or neighbor.get('mgmt_ip')
    device_id = neighbor.get('device_id')
    platform = neighbor.get('platform')
    capabilities = neighbor.get('capabilities') or neighbor.get('capability')

    hostname = mgmt_ip or device_id
    if not hostname:
        return None

    device_type = detect_device_type(platform, capabilities, device_id)
    return NetworkDevice(hostname, device_type, username, password)


def neighbor_identity(neighbor):
    """Create a stable identity tuple for de-duplication."""
    mgmt_ip = (neighbor.get('management_ip') or neighbor.get('mgmt_ip') or '').strip().lower()
    device_id = (neighbor.get('device_id') or '').strip().lower()
    platform = (neighbor.get('platform') or '').strip().lower()
    return (mgmt_ip, device_id, platform)


def device_identity(device):
    """Create a stable identity tuple for a NetworkDevice."""
    hostname = (device.hostname or '').strip().lower()
    device_type = (device.device_type or '').strip().lower()
    return (hostname, device_type)


def bfs_crawl(seed_devices, username, password, allow_types, max_depth=3, max_workers=10):
    """BFS crawler: process current batch fully, then expand neighbors into next batch."""
    seen_devices = set()
    seen_neighbors = set()
    current = list(seed_devices)
    all_results = []
    depth = 0

    while current and depth < max_depth:
        batch_results = []
        futures = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for device in current:
                key = device_identity(device)
                if key in seen_devices:
                    continue
                seen_devices.add(key)
                futures.append(executor.submit(crawl_device, device))

            for future in as_completed(futures):
                batch_results.append(future.result())

        all_results.extend(batch_results)

        next_batch = []
        for result in batch_results:
            for neighbor in result['cdp_neighbors']:
                neighbor_key = neighbor_identity(neighbor)
                if neighbor_key in seen_neighbors:
                    continue
                seen_neighbors.add(neighbor_key)
                new_device = build_device_from_neighbor(neighbor, username, password)
                if not new_device:
                    continue
                if new_device.device_type not in allow_types:
                    logging.info(
                        "Skipping neighbor %s (type=%s, platform=%s, capabilities=%s)",
                        new_device.hostname,
                        new_device.device_type,
                        neighbor.get('platform'),
                        neighbor.get('capabilities') or neighbor.get('capability')
                    )
                    continue
                key = device_identity(new_device)
                if key in seen_devices:
                    continue
                next_batch.append(new_device)

        current = next_batch
        depth += 1

    return all_results


def save_results(results, output_base):
    """Save results to JSON and CSV."""
    json_path = f"{output_base}.json"
    csv_path = f"{output_base}.csv"

    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2)

    fieldnames = [
        'hostname',
        'device_type',
        'status',
        'error',
        'neighbor_count',
    ]

    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                'hostname': r.get('hostname'),
                'device_type': r.get('device_type'),
                'status': 'OK' if not r.get('error') else 'ERROR',
                'error': r.get('error'),
                'neighbor_count': len(r.get('cdp_neighbors') or []),
            })

    print(f"Saved results: {json_path}, {csv_path}")


def main():
    parser = argparse.ArgumentParser(description="BFS CDP crawler")
    parser.add_argument("--csv", default="devices.csv", help="Seed device CSV file")
    parser.add_argument("--max-depth", type=int, default=3, help="Max BFS depth")
    parser.add_argument("--max-workers", type=int, default=10, help="Thread pool size")
    parser.add_argument("--output", default="crawl_results", help="Output base filename")
    parser.add_argument(
        "--allow-types",
        default="cisco_ios,cisco_nxos,cisco_xr,cisco_asa,cisco_wlc",
        help="Comma-separated Netmiko device_type allowlist"
    )
    parser.add_argument(
        "--log-file",
        default="crawler.log",
        help="Combined script and Netmiko session log file"
    )
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    devices = load_csv_devices(args.csv, username, password, session_log=args.log_file)
    if not devices:
        print("No valid devices found in CSV.")
        return

    allow_types = {t.strip() for t in args.allow_types.split(",") if t.strip()}
    logging.info("Allowlist types: %s", ",".join(sorted(allow_types)))

    results = bfs_crawl(
        devices,
        username,
        password,
        allow_types,
        max_depth=args.max_depth,
        max_workers=args.max_workers,
    )

    print(f"\nCrawled {len(results)} devices")
    for r in results:
        status = "OK" if not r['error'] else f"ERROR: {r['error']}"
        print(f"- {r['hostname']} ({r['device_type']}): {status}")

    save_results(results, args.output)


if __name__ == "__main__":
    main()
