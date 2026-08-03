import sys 
import asyncio

async def portscan(ip, port, sem):
    writer = None
    banner = b""
    flag_b = False
    async with sem:
        try:
            async with asyncio.timeout(3):
                reader, writer = await asyncio.open_connection(ip, port)

            async with asyncio.timeout(1):
                banner = await reader.read(512)

            if banner:
                flag_b = True

            return [port, flag_b, banner]

        except Exception:
            return [port, flag_b, banner]

        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()

async def main():
    try:
        if sys.argv[1] == "-help":
                print("Usage: Port_scanner.py -i [ip address] -p{-top} [port|range|multi]")
        else:
            sem = asyncio.Semaphore(200)
            tasks = []
            top = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,1723,3306,3389,5432,5900,6379,8080]
            ip = sys.argv[2] 
            result = [] #[port, open_closed, banners]
            if sys.argv[1] == "-i" and sys.argv[3] == "-p":
                portr = sys.argv[4].split('-')
                ports = sys.argv[4].split(',')
                flag_t = False
                if len(ports) > 1:
                    flag_p = True
                else:
                    flag_p = False
            else:
                flag_t = True
            #print(portr)
            if sys.argv[1] == "-i" and not flag_t:
                if len(portr) != 2 and not flag_p:
                    result = [await portscan(ip, int(portr[0]), sem)]
                elif len(portr) == 2:
                    for i in range(int(portr[0]), int(portr[1])):
                        tasks.append(asyncio.create_task(portscan(ip,i,sem))) #asyncio.create_task(portscan("192.168.1.6",i,sem))
                    result = await asyncio.gather(*tasks)
                else:
                    for p in range(0,len(ports)):
                        tasks.append(asyncio.create_task(portscan(ip,ports[p],sem)))
                    result = await asyncio.gather(*tasks)
            elif sys.argv[1] == "-i" and flag_t:
                for t in top:
                    tasks.append(asyncio.create_task(portscan(ip,t,sem)))
                result = await asyncio.gather(*tasks)
            #print(result)

            #result printing - [port, open(true) or closed(false), banner]
            for res in result:
                # if res[1]:
                #     if res[2]:
                #         print(f"{res[0]} OPEN {res[2].decode(errors='replace')}")
                #     else:
                #         print(f"{res[0]} OPEN")
                if res[2]:
                    print(f"{res[0]} {res[1]} {res[2].decode(errors='replace')}")
                else:
                    print(f"{res[0]} {res[1]}")
    except IndexError as e:
        print("debug 1")
        print(e)


while True:
    try:
        asyncio.run(main())
        break
    except Exception as e:
        print("Usage: Port_scanner.py -i [ip address] -p [port]")
        print(e)
        break