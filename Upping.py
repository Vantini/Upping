import json
import sys
import threading
import time

import certifi
import nmap
import requests
import dns.resolver


def options():
    op = input("Option: ")
    if op == str(1):
        ip = input("IP: ")
        nmaping(ip)
    elif op == str(2):
        site = input("Site: ")
        list_dir(site)
    elif op == str(3):
        domain = input("Domain: ")
        list_dns(domain)

    else:
        print("Select a valid option.")
        options()


def nmaping(ip):
    def loading_animation(stop_event):
        while not stop_event.is_set():
            for state in ["[ scanning ]", "[ SCANNING ]", "[ scanning ]", "[ SCANNING ]"]:
                if stop_event.is_set():
                    break
                sys.stdout.write('\r' + state)
                sys.stdout.flush()
                time.sleep(0.5)
        sys.stdout.write('\r' + ' ' * len(state) + '\r')  # Clear the line
        sys.stdout.flush()

    stop_event = threading.Event()
    t = threading.Thread(target=loading_animation, args=(stop_event,))
    t.start()

    try:
        # Executa um scan rápido para identificar todas as portas abertas
        scan_q = nmap.PortScanner()
        quick_scan = "-Pn -T5 -p-"
        scan_q.scan(ip, arguments=quick_scan)

        for proto in scan_q[ip].all_protocols():
            prt = proto

        # Executa um scan mais detalhado em cima das portas abertas
        ports = scan_q[ip][prt].keys()
        ports_list = [str(port) for port in ports]  # Converte as portas para strings
        ports_str = ",".join(ports_list)  # Junta as portas em uma string separada por vírgulas
        scan_a = nmap.PortScanner()
        all_scan = "-Pn -A -p {}".format(ports_str)
        scan_a.scan(ip, arguments=all_scan)

        with open('scan_results.txt', 'w') as file:
            file.write(str(json.dump(scan_a[ip], file, indent=4)))
    finally:
        stop_event.set()
        t.join()
        print("\nScan complete!")


def list_dir(site):
    wordlist_file = input("Wordlist (all path): ")

    try:
        with open(wordlist_file, "r") as file:
            wordlist = file.read().splitlines()
    except FileNotFoundError:
        print(f"Arquivo {wordlist_file} não encontrado.")
        sys.exit(1)
    for word in wordlist:
        if "https" or "http" in site:
            url = f"{site}{word}"
        else:
            url = f"https://{site}/{word}"
        response = requests.get(url, verify=certifi.where())
        with open("dir_results.txt", "a") as file:
            if response.status_code == 200:
                print(f"{url} -> status code: {response.status_code}\n", end="\r")
                r = "{} -> exists! (status code: 200)\n".format(url)
                file.write(r)
            else:
                print(f"{url} -> status code: {response.status_code}\n", end="\r")

    # http://testphp.vulnweb.com/


def list_dns(domain):

    wordlist = input("Wordlist (all path): ")
    resolver = dns.resolver.Resolver()

    try:
        with open(wordlist, "r") as arq:
            sub_doms = arq.read().splitlines()
    except Exception as e:
        print(f"Erro ao abrir a wordlist: {e}")
        sys.exit()

    try:
        with open("list_dns_results.txt", "w") as out:
            for sub_dom in sub_doms:
                try:
                    sub_target = "{}.{}".format(sub_dom, domain)
                    resultados = resolver.resolve(sub_target, "A")
                    for resultado in resultados:
                        print ("{} -> {}".format(sub_target, resultado))
                        out.write("{} -> {}\n".format(sub_target, resultado))
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    pass
    except KeyboardInterrupt:
        print("\nExecução interrompida pelo usuário.")
        sys.exit()

def main():
    print("██╗   ██╗██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ ")
    print("██║   ██║██╔══██╗██╔══██╗██║████╗  ██║██╔════╝ ")
    print("██║   ██║██████╔╝██████╔╝██║██╔██╗ ██║██║  ███╗")
    print("██║   ██║██╔═══╝ ██╔═══╝ ██║██║╚██╗██║██║   ██║")
    print("╚██████╔╝██║     ██║     ██║██║ ╚████║╚██████╔╝")
    print(" ╚═════╝ ╚═╝     ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ")
    print("     [--== Created by: Vantiniedu ==--]        ")
    print("         --== Version: 1.0 ==--                ")
    print(" [--== Welcome to the Future of Scanning ==--] ")

    print("\nWhat you wanna do?\n")
    print("1 - Nmaping")
    print("2 - Directory enum")
    print("3 - DNS enum")
    options()


if __name__ == '__main__':
    main()
