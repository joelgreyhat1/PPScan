import socket
import threading
import queue
import sys
import ipaddress

def scanPort(target_ip, start_port, end_port, port_queue, results):
    while True:
        port = port_queue.get()
        if port is None:
            break
        sys.stdout.write(f"\rScanning port {port}")
        sys.stdout.flush()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                results[port] = "Open"
        port_queue.task_done()
    sys.stdout.write('\n')
def specificIpScan():
    print("=== Specific IP Scanning ===")
    try:
        target_ip = input("Enter an IP address to scan: ")
        ipaddress.IPv4Address(target_ip)
        start_port = int(input("Input the starting port number: "))
        end_port_input = input("Input the ending port number (hit the Enter key to use starting port): ")
        if end_port_input:
            end_port = int(end_port_input)
        else:
            end_port = start_port
        if end_port != start_port and end_port < start_port:
            print("Ending port must be greater than or equal to the starting port.")
            return
    except ValueError:
        print("Invalid input. Please enter a valid IP address and port number.")
        return
    results = {}
    scan(target_ip, start_port, end_port, results)
    print(f"\nOpen ports on {target_ip}:")
    for port, status in sorted(results.items()):
        if status == "Open":
            print(f"Port {port}: {status}")
def calculate_end_ip(start_ip, subnet_mask):
    ip_parts = start_ip.split('.')
    subnet_mask_parts = subnet_mask.split('.')
    ip_int = [int(part) for part in ip_parts]
    mask_int = [int(part) for part in subnet_mask_parts]
    end_ip_int = [ip_int[i] | (~mask_int[i] & 0xff) for i in range(4)]
    return '.'.join(map(str, end_ip_int))
def suggest_subnet_mask(ip_parts):
    first_octet = int(ip_parts[0])
    if 1 <= first_octet <= 126:
        return '255.0.0.0'  
    elif 128 <= first_octet <= 191:
        return '255.255.0.0' 
    elif 192 <= first_octet <= 223:
        return '255.255.255.0' 
    return '255.255.255.0' 
def scanAnIpRange():
    print("=== IP Range Scan ===")
    try:
        start_ip = input("Enter the starting IP address: ")
        ip_parts = start_ip.split('.')

        subnet_mask = suggest_subnet_mask(ip_parts)
        print(f"Suggested subnet mask: {subnet_mask}")

        suggested_end_ip = calculate_end_ip(start_ip, subnet_mask)
        print(f"Suggested ending IP address: {suggested_end_ip}")

        end_ip = input("Enter the ending IP address (press Enter to use suggested): ")
        if not end_ip:
            end_ip = suggested_end_ip
        else:
            ipaddress.IPv4Address(end_ip)

        start_port = int(input("Enter the starting port number: "))
        end_port_input = input("Enter the ending port number (press Enter to use starting port): ")
        if end_port_input:
            end_port = int(end_port_input)
        else:
            end_port = start_port
        if end_port != start_port and end_port < start_port:
            print("Ending port must be greater than or equal to the starting port.")
            return
    except ValueError:
        print("Invalid input. Please enter valid IP addresses, subnet mask, and port numbers.")
        return
    ip_range = ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip))
    all_results = {}
    for network in ip_range:
        for host in network:
            results = {}
            print(f"\nScanning ports for {host}...")
            sys.stdout.flush()  # Ensure buffer is flushed before scan
            scan(str(host), start_port, end_port, results)
            all_results[host] = results
    for ip, results in all_results.items():
        print(f"\nOpen ports on {ip}:")
        for port, status in sorted(results.items()):
            print(f"Port {port}: {status}")
def scan(target_ip, start_port, end_port, results):
    num_threads = 100
    port_queue = queue.Queue()
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=scanPort, args=(target_ip, start_port, end_port, port_queue, results))
        thread.start()
        threads.append(thread)
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    port_queue.join()
    for _ in range(num_threads):
        port_queue.put(None)

    for thread in threads:
        thread.join()
while True:
    print("\n= PORT SCANNER =")
    print("Select the scan type:")
    print("1. Specific Ip Scan")
    print("2. Ip Range")
    print("0. Quit")

    scan_type = input("Enter your choice (0, 1, or 2): ")

    if scan_type == "1":
        specificIpScan()
    elif scan_type == "2":
        scanAnIpRange()
    elif scan_type == "0":
        print("Exiting...")
        break
    else:
        print("Invalid choice. Please enter 0, 1, or 2.")
