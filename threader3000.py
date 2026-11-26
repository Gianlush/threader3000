#!/usr/bin/python3
# Threader3000 - Multi-threader Port Scanner
# A project by The Mayor
# v1.0.7 (modified: multi-target input from file, like nmap -iL)
# https://github.com/dievus/threader3000
# Licensed under GNU GPLv3 Standards.  https://www.gnu.org/licenses/gpl-3.0.en.html

import socket
import os
import time
import threading
import sys
from queue import Queue
from datetime import datetime

THREADS = 200
LIVE_HOSTS_FILE = "live_hosts.txt"


def load_targets(user_input):
    """
    Ritorna (targets, from_file, label)
      targets   : lista di tuple (originale, ip risolto), senza duplicati
      from_file : True se l'input era un file (equivalente di nmap -iL)
      label     : nome usato per la cartella di output e per -oA
    Se l'input e' un path a file esistente, viene letto un target per riga
    (righe vuote e commenti '#' ignorati). Altrimenti e' un singolo IP/URL.
    """
    user_input = user_input.strip()
    from_file = os.path.isfile(user_input)

    if from_file:
        with open(user_input, "r") as f:
            raw = [l.strip() for l in f]
        raw = [l for l in raw if l and not l.startswith("#")]
        label = os.path.splitext(os.path.basename(user_input))[0]
    else:
        raw = [user_input]
        label = user_input

    targets, seen = [], set()
    for entry in raw:
        try:
            ip = socket.gethostbyname(entry)
        except (UnboundLocalError, socket.gaierror):
            print("[-] Impossibile risolvere '{}', salto [-]".format(entry))
            continue
        if ip in seen:
            continue
        seen.add(ip)
        targets.append((entry, ip))

    return targets, from_file, label


# Main Function
def main():
    socket.setdefaulttimeout(0.30)
    print_lock = threading.Lock()
    # ip -> lista di porte aperte
    discovered = {}

    # Welcome Banner
    print("-" * 60)
    print("        Threader 3000 - Multi-threaded Port Scanner          ")
    print("                       Version 1.0.7                    ")
    print("                   A project by The Mayor               ")
    print("-" * 60)
    time.sleep(1)
    user_input = input("Enter your target IP address, URL or path to a file with targets (one per line): ")

    try:
        targets, from_file, label = load_targets(user_input)
    except OSError as e:
        print("\n[-]Cannot read target file: {}[-]\n".format(e))
        sys.exit()

    if not targets:
        print("\n[-]Invalid format. Please use a correct IP or web address (or a valid target file)[-]\n")
        sys.exit()

    # Banner
    print("-" * 60)
    if from_file:
        print("Scanning {} targets from file {}".format(len(targets), user_input))
    else:
        print("Scanning target " + targets[0][1])
    print("Time started: " + str(datetime.now()))
    print("-" * 60)
    t1 = datetime.now()

    current_ip = {"ip": None}  # non usato dai worker: l'IP viaggia nella coda

    def portscan(ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            with print_lock:
                if from_file:
                    print("{}: port {} is open".format(ip, port))
                else:
                    print("Port {} is open".format(port))
                discovered.setdefault(ip, []).append(port)
        except (ConnectionRefusedError, AttributeError, OSError):
            pass
        finally:
            s.close()

    def threader():
        while True:
            ip, port = q.get()
            portscan(ip, port)
            q.task_done()

    q = Queue()

    # Pool di thread creato una sola volta e riusato per tutti gli host
    for _ in range(THREADS):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for idx, (orig, ip) in enumerate(targets, 1):
        if from_file:
            with print_lock:
                print("\n[{}/{}] Target {} ({})".format(idx, len(targets), orig, ip))
        for port in range(1, 65536):
            q.put((ip, port))
        q.join()

    t2 = datetime.now()
    total = t2 - t1
    print("Port scan completed in " + str(total))
    print("-" * 60)

    # Riepilogo e costruzione del comando nmap
    for ip in discovered:
        discovered[ip].sort()

    if from_file:
        print("Open ports per host:")
        for orig, ip in targets:
            ports = discovered.get(ip, [])
            print("  {:<16} {}".format(ip, ",".join(map(str, ports)) if ports else "-"))
        print("-" * 60)

    all_ports = sorted({p for plist in discovered.values() for p in plist})
    ports_str = ",".join(map(str, all_ports))
    live_ips = [ip for _, ip in targets if ip in discovered]

    if from_file:
        # -iL: il file con gli host vivi viene scritto nella cartella di output
        nmap = "nmap -p{ports} -sV -sC -T4 -Pn -oA {label} --open -iL {lf}".format(
            ports=ports_str, label=label, lf=LIVE_HOSTS_FILE)
    else:
        nmap = "nmap -p{ports} -sV -sC -T4 -Pn -oA {ip} --open {ip}".format(
            ports=ports_str, ip=label)

    print("Threader3000 recommends the following Nmap scan:")
    print("*" * 60)
    print(nmap)
    print("*" * 60)
    if from_file and not live_ips:
        print("[!] Nessun host con porte aperte trovato: nmap non verra' suggerito")

    # Nmap Integration
    def automate():
        choice = '0'
        while choice == '0':
            print("Would you like to run Nmap or quit to terminal?")
            print("-" * 60)
            print("1 = Run suggested Nmap scan")
            print("2 = Run another Threader3000 scan")
            print("3 = Exit to terminal")
            print("-" * 60)
            choice = input("Option Selection: ")
            if choice == "1":
                if not all_ports:
                    print("No open ports found, nothing to scan with Nmap.")
                    choice = '0'
                    continue
                try:
                    print(nmap)
                    os.mkdir(label)
                    os.chdir(label)
                    if from_file:
                        with open(LIVE_HOSTS_FILE, "w") as f:
                            f.write("\n".join(live_ips) + "\n")
                    os.system(nmap)
                    t3 = datetime.now()
                    total1 = t3 - t1
                    print("-" * 60)
                    print("Combined scan completed in " + str(total1))
                    print("Press enter to quit...")
                    input()
                except FileExistsError as e:
                    print(e)
                    exit()
            elif choice == "2":
                main()
            elif choice == "3":
                sys.exit()
            else:
                print("Please make a valid selection")
                automate()

    automate()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        quit()
