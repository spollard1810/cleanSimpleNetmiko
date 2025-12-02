import re
import ipaddress
import csv


class NetworkParser:
    """Parser for network device command outputs"""
    
    @staticmethod
    def parse_ip_addresses_to_cidr(output):
        """Parse 'ip address X.X.X.X Y.Y.Y.Y' lines and convert to CIDR with ranges"""
        pattern = r'ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
        matches = re.findall(pattern, output)
        
        parsed_data = []
        for ip_str, mask_str in matches:
            try:
                network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                parsed_data.append({
                    'cidr': str(network),
                    'start': str(network.network_address),
                    'end': str(network.broadcast_address)
                })
            except Exception as e:
                print(f"Error parsing {ip_str}/{mask_str}: {e}")
        
        return parsed_data
    
    @staticmethod
    def save_ip_addresses_to_csv(results, output_file="ip_addresses.csv"):
        """Save parsed IP addresses from all devices to CSV"""
        all_parsed_ips = []
        
        for result in results:
            if result['success']:
                parsed = NetworkParser.parse_ip_addresses_to_cidr(result['output'])
                for entry in parsed:
                    entry['hostname'] = result['hostname']
                    all_parsed_ips.append(entry)
        
        if all_parsed_ips:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Hostname', 'CIDR', 'Start IP', 'End IP'])
                for entry in all_parsed_ips:
                    writer.writerow([
                        entry['hostname'],
                        entry['cidr'],
                        entry['start'],
                        entry['end']
                    ])
            
            print(f"\nParsed {len(all_parsed_ips)} IP addresses")
            print(f"Output written to: {output_file}")
            
            # Display sample
            print("\nSample output:")
            for entry in all_parsed_ips[:5]:
                print(f"{entry['cidr']} {entry['start']} - {entry['end']}")
            
            return all_parsed_ips
        else:
            print("No IP addresses found to parse")
            return []

