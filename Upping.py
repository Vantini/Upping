# Utilizado para formatar a saída do Nmaping
import json

# Utilizado para animações e para comandos nativos
import sys
import threading
import time

# Utilizados para requisições em geral
import requests
import certifi

# Utilizado para o Nmaping
import nmap

# Utilizado para o DNS Enum
import dns.resolver

# Utilizado para o Web Crawler
from bs4 import BeautifulSoup


def options():
    op = input("Option: ")
    if op == str(1):
        ip = input("IP: ")
        nmaping(ip)
    elif op == str(2):
        url = str(input("url: "))
        list_dir(url)
    elif op == str(3):
        domain = input("Domain: ")
        list_dns(domain)
    elif op == str(4):
        url = input("Url: ")
        crawling(url)

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
        sys.stdout.write('\r' + ' ' * len(state) + '\r')  # Limpa a linha
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

        with open(f"scan_{ip}_results.txt", 'w') as file:
            file.write(str(json.dump(scan_a[ip], file, indent=4)))
    finally:
        stop_event.set()
        t.join()
        print("\nScan complete!")


def list_dir(site):
    wordlist_file = input("Wordlist (all path): ")
    extensions = input("Any extensions? (e.g: .php,.html): ").split(',')

    # Remove espaços extras e garante que as extensões comecem com um ponto
    extensions = [ext.strip() for ext in extensions]
    extensions = [f'.{ext}' if not ext.startswith('.') else ext for ext in extensions]

    # Abre o arquivo da wordlist
    try:
        with open(wordlist_file, "r") as file:
            wordlist = file.read().splitlines()
    except FileNotFoundError:
        print(f"File {wordlist_file} not found.")
        sys.exit(1)

    # Faz a verificação se a entrada do usuário já contém ou não http/https
    for word in wordlist:
        if "https" in str(site) or "http" in str(site):
            base_url = f"{site}{word}"
        else:
            base_url = f"https://{site}/{word}"

        # Requisição sem a extensão
        response = requests.get(base_url, verify=certifi.where())

        with open(f"dir_{site}_results.txt", "a") as file:
            if response.status_code == 200:
                print(f"{base_url} -> status code: {response.status_code}")
                r = "{} -> exists! (status code: 200)\n".format(base_url)
                file.write(r)
            else:
                print(f"{base_url} -> status code: {response.status_code}")

            # Requisição com a extensão
            for ext in extensions:
                if ext:  # Check if the extension is not empty
                    urlext = f"{base_url}{ext}"
                    responsext = requests.get(urlext, verify=certifi.where())

                    if responsext.status_code == 200:
                        print(f"{urlext} -> status code: {responsext.status_code}")
                        rxt = "{} -> exists! (status code: 200)\n".format(urlext)
                        file.write(rxt)
                    else:
                        print(f"{urlext} -> status code: {responsext.status_code}")


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
        with open(f"dns_{domain}_results.txt", "w") as out:
            for sub_dom in sub_doms:
                try:
                    sub_target = "{}.{}".format(sub_dom, domain)
                    resultados = resolver.resolve(sub_target, "A")
                    for resultado in resultados:
                        print("{} -> {}".format(sub_target, resultado))
                        out.write("{} -> {}\n".format(sub_target, resultado))
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    pass
    except KeyboardInterrupt:
        print("\nExecução interrompida pelo usuário.")
        sys.exit()


def crawling(url):
    rest = []
    done = set()
    header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko"}
    rest.append(url)

    try:
        with open(f"{url}_crawling.txt", "w") as file:
            try:
                while rest:
                    url = rest.pop()
                    if not url.startswith("http"):
                        url = f"https://{url}"
                    try:
                        try:
                            response = requests.get(url, headers=header, verify=certifi.where())
                            html = response.text
                        except KeyboardInterrupt:
                            sys.exit(0)
                    except:
                        html = None

                    if html:
                        try:
                            crawl = BeautifulSoup(html, "html.parser")
                            tags = crawl.find_all("a", href=True)
                            links = []
                            for tag in tags:
                                link = tag["href"]
                                if link.startswith("http"):
                                    links.append(link)
                        except:
                            links = []

                    if links:
                        for link in links:
                            if link not in done and link not in rest:
                                rest.append(link)

                    print(f"Crawling: {url}")
                    file.write(f"Encountered: {url}\n")
                    done.add(url)

            except Exception as error:
                print(error)
    except Exception as error:
        print("Erro: ", error)


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
    print("4 - Web Crawling")
    try:
        options()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
