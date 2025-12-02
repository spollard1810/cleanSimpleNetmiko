import csv
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from Core import NetworkDevice, NetworkParser


def loadCSV(filename):
    """Load device list from CSV file with hostname and deviceType headers"""
    devices = []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            devices.append({
                'hostname': row['hostname'],
                'deviceType': row['deviceType']
            })
    return devices


def display_menu():
    """Display parsing options menu"""
    print("\n" + "="*80)
    print("SELECT PARSING MODE")
    print("="*80)
    print("1. Run command (raw output only)")
    print("2. Run command with NTC-Templates auto parser")
    print("3. Run command with IP address parser (CIDR converter)")
    print("="*80)
    
    while True:
        choice = input("Enter choice (1-3): ").strip()
        if choice in ['1', '2', '3']:
            return int(choice)
        print("Invalid choice. Please enter 1, 2, or 3.")


def execute_command_on_device(hostname, device_type, username, password, command, use_textfsm=False):
    """Connect to device, execute command, and return results"""
    device = NetworkDevice(hostname, device_type, username, password)
    result = {
        'hostname': hostname,
        'success': False,
        'output': None,
        'parsed_output': None,
        'error': None
    }
    
    try:
        print(f"Connecting to {hostname}...")
        device.connect()
        print(f"Connected to {hostname}. Executing command...")
        
        if use_textfsm:
            # Use TextFSM parsing via Netmiko
            output = device.connection.send_command(command, use_textfsm=True)
            result['parsed_output'] = output
            result['output'] = str(output)
        else:
            output = device.sendCommand(command)
            result['output'] = output
        
        result['success'] = True
        print(f"Command completed on {hostname}")
    except Exception as e:
        result['error'] = str(e)
        print(f"Error on {hostname}: {e}")
    finally:
        device.disconnect()
    
    return result


def main():
    # Load devices from CSV
    csv_file = input("Enter CSV filename (default: devices.csv): ").strip()
    if not csv_file:
        csv_file = "devices.csv"
    
    devices = loadCSV(csv_file)
    print(f"Loaded {len(devices)} devices")
    
    # Get credentials
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    # Display menu and get parsing mode
    parse_mode = display_menu()
    
    # Get command to execute
    command = input("\nCommand to execute: ")
    
    # Determine if using TextFSM
    use_textfsm = (parse_mode == 2)
    
    # Execute on all devices using thread pool
    max_workers = min(20, len(devices))
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                execute_command_on_device,
                device['hostname'],
                device['deviceType'],
                username,
                password,
                command,
                use_textfsm
            ): device for device in devices
        }
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
    
    # Display results to console
    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)
    
    for result in results:
        print(f"\n{'='*80}")
        print(f"Device: {result['hostname']}")
        print(f"Status: {'SUCCESS' if result['success'] else 'FAILED'}")
        print(f"{'='*80}")
        
        if result['success']:
            print(result['output'])
        else:
            print(f"Error: {result['error']}")
    
    # Handle output based on mode
    print("\n" + "="*80)
    print("SAVING OUTPUT")
    print("="*80)
    
    if parse_mode == 1:
        # Raw output - save to text file
        output_file = "output.txt"
        with open(output_file, 'w') as f:
            for result in results:
                f.write(f"{'='*80}\n")
                f.write(f"Device: {result['hostname']}\n")
                f.write(f"Status: {'SUCCESS' if result['success'] else 'FAILED'}\n")
                f.write(f"{'='*80}\n")
                if result['success']:
                    f.write(result['output'])
                    f.write("\n\n")
                else:
                    f.write(f"Error: {result['error']}\n\n")
        print(f"Raw output saved to: {output_file}")
    
    elif parse_mode == 2:
        # NTC-Templates mode - save parsed output to CSV
        output_file = "output.csv"
        all_parsed_data = []
        
        for result in results:
            if result['success'] and result.get('parsed_output'):
                parsed = result['parsed_output']
                # If parsed output is a list of dicts (typical TextFSM output)
                if isinstance(parsed, list) and len(parsed) > 0:
                    for entry in parsed:
                        if isinstance(entry, dict):
                            entry['hostname'] = result['hostname']
                            all_parsed_data.append(entry)
        
        if all_parsed_data:
            # Get all unique keys from all entries
            all_keys = set()
            for entry in all_parsed_data:
                all_keys.update(entry.keys())
            
            fieldnames = ['hostname'] + sorted([k for k in all_keys if k != 'hostname'])
            
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_parsed_data)
            
            print(f"Parsed output saved to: {output_file}")
            print(f"Total entries: {len(all_parsed_data)}")
        else:
            print("No structured data to save. Check if command supports TextFSM parsing.")
    
    elif parse_mode == 3:
        # IP address parser mode - save to CSV
        NetworkParser.save_ip_addresses_to_csv(results, "output.csv")


if __name__ == "__main__":
    main()

