import requests
import nmap
import sys
import socket
import subprocess
import argparse
import json

scanner = nmap.PortScanner()

def get_all_hosts(iface:str,net:str):
    hosts_scan = scanner.scan(hosts=net,arguments='-sn -T5 -e {}'.format(iface))
    hosts = []
    for ip in hosts_scan["scan"]:
        hosts.append(ip)
    return hosts

def scan_tcp_ports(iface:str,ip:str):
    ports_info = []
    try:
        tcp_scan = scanner.scan(hosts=ip,ports='1-1024',arguments="-sV --min-rate 5000 -v")
    
        for port in tcp_scan["scan"][ip]['tcp']:
            port_info = tcp_scan["scan"][ip]['tcp'][port]
            print("\t\t{}:\t{} {} {}".format(port,port_info['name'],port_info['product'], port_info['version']))
            ports_info.append({"port":port,"service":port_info['name'],"product":port_info['product'],"version":port_info['version']})
    except KeyboardInterrupt:
        print("Escaneo de puertos detenido")
        exit(1)
    except:
        print("\t\tNo open ports")
    
    return ports_info

def scan_udp_ports(iface:str,ip:str):
    ports_info = []
    try:
        udp_ports = scanner.scan(hosts=ip,ports='1-1024',arguments="-sU --open --min-rate 5000 -v",sudo=True)["scan"][ip]['udp'].keys()
        ports_string = ','.join(str(e) for e in udp_ports)
        udp_scan = scanner.scan(hosts=ip,ports=ports_string,arguments="-sU -sV --open -T5 -v",sudo=True)
    
        for port in udp_scan["scan"][ip]['udp']:
            port_info = udp_scan["scan"][ip]['udp'][port]
            print("\t\t{}:\t{} {} {}".format(port,port_info['name'],port_info['product'], port_info['version']))
            ports_info.append({"port":port,"service":port_info['name'],"product":port_info['product'],"version":port_info['version']})
    except KeyboardInterrupt:
        print("Escaneo de puertos detenido")
        exit(1)
    except:
        print("\t\tNo open ports",)
    
    return ports_info

def verify_network_address(net:str):
    split = net.split('.')
    if len(split) != 4:
        print("Direccion de red invalida, la direccion de red debe seguir la notacion CIDR (ipv4/logitud-prefijo). Ej 192.168.1.0/24")
        exit(1)
    if split[-1].find('/') == -1:
        print("Direccion de red invalida, la direccion de red debe seguir la notacion CIDR (ipv4/logitud-prefijo). Ej 192.168.1.0/24")
        exit(1)

def upload_info(info:dict):
    try:
        r = requests.post('http://127.0.0.1/example/fake_url.php',json=info)
        print("[OK]")
    except:
        print("[FAIL] no se pudo establecer conexion con el servidor. ")

def save_file(filename:str,file_data:dict):
    output_file = open(filename,"w+")
    json.dump(file_data,output_file,indent=2)
    output_file.close()


def main():
    parser = argparse.ArgumentParser(description="Uso: python scanner.py -i <Interfaz> <Direccion de red>")
    parser.add_argument('net',type=str,help="Indica la direccion de red. Ej: 192.168.1.0/24")
    parser.add_argument('-i',type=str,default='eth0',help="Elige la interfaz de red con la cual escanear")
    parser.add_argument('-o',type=str,default='Output.json',help="Nombre del fichero al que se exportara la informacion del escaneo")
    args = parser.parse_args()
    net = args.net
    iface = args.i
    output_file_name = args.o

    verify_network_address(net)

    subprocess.call(["/usr/bin/sudo", "/usr/bin/id"]) #Requerir permisos de super usuario
    print("Buscando maquinas en la red {}. . . . ".format(net))
    hosts = get_all_hosts(iface,net)

    if len(hosts) == 0:
        print("[FAIL] no se encontraron hosts en la red {} para la interfaz {}".format(net,iface))
        exit(1)

    final_report = {}

    for host in hosts:
        print("IP ",host,"\n==============================")
        print("\tTCP:")
        tcp_results = scan_tcp_ports(iface,host)
        print("\tUDP:")
        udp_results = scan_udp_ports(iface,host)

        final_report[host] = {"tcp":tcp_results,"udp":udp_results,}
        print("------------------------------\n")

    
    print("Enviando resultados a la url http://127.0.0.1/example/fake_url.php. . . .")
    upload_info(final_report)
    print("Generando fichero Output.json. . . .")
    save_file(output_file_name,final_report)
    print("[OK]")


if __name__ == '__main__':
    main()
















# print ("Scanner")
# ip_addr = input ("INserte la IP a escanear:")

# resp = input ("""Seleccione un tipo de escaneo:\n1) Escaneo de sistema operativo\n2) Escaneo UDP\n""")

# if resp == "1":
#     print("Nmap version ",scanner.nmap_version())
#     scanner.scan(ip_addr,'1-1024',"-O","-v")
#     print(scanner.scaninfo())
#     print("estado IP ", scanner[ip_addr].state())

#     for port in scanner[ip_addr]['tcp'].keys():
#         print("Port {}/tcp open".format(port)) 
    
# elif resp == "2":
#     print("Nmap version ",scanner.nmap_version())
#     scanner.scan(ip_addr,'1-2050',"-sU --min-rate 5000 --open","-v",)
#     print(scanner.scaninfo())
#     print("estado IP ", scanner[ip_addr].state())

#     for port in scanner[ip_addr]['udp'].keys():
        # print("Port {}/udp open".format(port)) 