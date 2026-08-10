import asyncio
import argparse

async def portscan(ip, port, sem):
    banner = b""
    is_open = False
    
    async with sem:
        try:
            # 1. First try to open the connection
            async with asyncio.timeout(3):
                reader, writer = await asyncio.open_connection(ip, port)
            
            is_open = True  # If we reach here, the port is open

            # 2. Then try to grab the banner
            try:
                async with asyncio.timeout(1):
                    banner = await reader.read(512)
            except TimeoutError:
                # Port is open, but no banner was sent in time
                pass

        except Exception:
            # Connection failed (closed/filtered)
            pass

        finally:
            # Safely clean up the connection if it was created
            if 'writer' in locals() and writer is not None:
                writer.close()
                await writer.wait_closed()
                
        return port, is_open, banner

def get_ports(args):
    """Helper function to figure out which ports to scan based on arguments."""
    top_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,1723,3306,3389,5432,5900,6379,8080]
    
    if args.top:
        return top_ports
    
    if args.ports:
        if '-' in args.ports:
            # Handle range (e.g., 20-80)
            start, end = args.ports.split('-')
            return list(range(int(start), int(end) + 1))
        elif ',' in args.ports:
            # Handle comma separated (e.g., 22,80,443)
            return [int(p) for p in args.ports.split(',')]
        else:
            # Handle single port
            return [int(args.ports)]
            
    # Default to top ports if nothing was provided
    return top_ports

async def main():
    parser = argparse.ArgumentParser(description="Asyncio Port Scanner")
    parser.add_argument('-i', dest='ip', required=True, help="IP address to scan")
    
    # Create a mutually exclusive group so the user can't use -p and -top at the same time
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', dest='ports', help="Port(s) to scan (single, range x-y, or multi x,y,z)")
    group.add_argument('-top', action='store_true', help="Scan top common ports")

    args = parser.parse_args()

    ip = args.ip
    ports_to_scan = get_ports(args)
    sem = asyncio.Semaphore(200)
    
    print(f"Scanning {len(ports_to_scan)} ports on {ip}...")

    # Create and gather all tasks
    tasks = [asyncio.create_task(portscan(ip, port, sem)) for port in ports_to_scan]
    results = await asyncio.gather(*tasks)

    # Print results - format: port open/closed banner
    for port, is_open, banner in results:
        if banner:
            # .strip() removes trailing newlines from the banner for cleaner output
            clean_banner = banner.decode(errors='replace').strip()
            print(f"{port} {is_open} {clean_banner}")
        else:
            print(f"{port} {is_open}")

if __name__ == "__main__":
    try:
        # This is the modern Python way to run an async main function
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")