from scapy.layers.dot11 import Dot11, sniff
from os import system, geteuid, path, name
import sys
import colorama
from colorama import Fore
import subprocess

colorama.init(autoreset=True)

# Логотип программы
program_logo = f"""
{Fore.LIGHTRED_EX}  _____        __          ___ ______ _  _____                                 
 / ____|       \ \        / (_)  ____(_)/ ____|                                
| |  __  ___ _ _\ \  /\  / / _| |__   _| (___   ___ __ _ _ __  _ __   ___ _ __ 
| | |_ |/ _ \ '_ \ \/  \/ / | |  __| | |\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |__| |  __/ | | \  /\  /  | | |    | |____) | (_| (_| | | | | | | |  __/ |   
 \_____|\___|_| |_|\/  \/   |_|_|    |_|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                
"""

# Инструкция по использованию программы
usage_info = f"""
{Fore.LIGHTYELLOW_EX}╭────────────────────────━━━━━━━━━━━━━━━━━━━━━━────────────────────╮
| {Fore.LIGHTGREEN_EX}Использование » python {path.basename(__file__)} [mode] [iface] [params] {Fore.LIGHTYELLOW_EX}|
|                                                                  |
| {Fore.LIGHTGREEN_EX}Режимы:                                                          {Fore.LIGHTYELLOW_EX}|
|  -n      {Fore.WHITE}Просмотр информации об окружающих сетях                 {Fore.LIGHTYELLOW_EX}|
|  -uc     {Fore.WHITE}Просмотр пользователей, подключенных к сети             {Fore.LIGHTYELLOW_EX}|
|  -m      {Fore.WHITE}Режим просмотра трафика                                 {Fore.LIGHTYELLOW_EX}|
|                                                                  |
| {Fore.LIGHTGREEN_EX}Примеры:                                                         {Fore.LIGHTYELLOW_EX}|
|  python {path.basename(__file__)} -uc wlan0mon 00:1A:2B:3C:4D:5E 60      {Fore.LIGHTYELLOW_EX}|
|  python {path.basename(__file__)} -m wlan0mon                            {Fore.LIGHTYELLOW_EX}|
╰────────────────────────━━━━━━━━━━━━━━━━━━━━━━────────────────────╯
"""

class GenWiFiScanner:
    # Сканирование доступных Wi-Fi сетей
    def scan_wifi_networks(self):
        print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.GREEN}Сканирование, пожалуйста, подождите...")
        try:
            if sys.platform.startswith('win'):
                result = subprocess.check_output(['netsh', 'wlan', 'show', 'network'], stderr=subprocess.DEVNULL)
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                result = subprocess.check_output(['iwlist', 'scan'], stderr=subprocess.DEVNULL)
            else:
                print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Неподдерживаемая платформа")
                return None
            return result.decode('utf-8')
        except Exception as e:
            print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Ошибка при сканировании: {Fore.LIGHTRED_EX}{e}")
            return None

# Слежение за пользователями, подключенными к точке доступа
    def sniff_ap_clients(self, ap_mac: str, iface: str, timeout: int = 15):
        clients = set()

        def packet_handler(packet):
            if packet.haslayer(Dot11) and packet.addr3 == ap_mac.lower():
                if packet.addr2 not in clients:
                    print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» Обнаружен пользователь: {Fore.LIGHTGREEN_EX}{packet.addr2}")
                    clients.add(packet.addr2)

        print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.GREEN}Пожалуйста, подождите...")
        try:
            sniff(prn=packet_handler, iface=iface, store=0, timeout=timeout)
        except Exception as e:
            print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Ошибка: {Fore.LIGHTRED_EX}{e}")
        return clients

# Отображение информации об окружающих сетях
    def show_networks_around(self):
        results = self.scan_wifi_networks()
        if results:
            networks = self.parse_results(results)
            for iface in networks:
                print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» \n=======================\nИнтерфейс: {Fore.GREEN}{iface['iface']}")
                for network in iface.get("results", []):
                    print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» \nID: {network.get('id')}\nИмя: {network.get('ESSID')}\nMAC: {network.get('MAC')}\nКлюч шифрования: {network.get('e_key')}\nЧастота: {network.get('frequency')}\nКанал: {network.get('channel')}\nУровень сигнала: {network.get('signal_level')}\nПоследний маяк: {network.get('last_beacon')}\nБезопасность: {network.get('Secure')}")
                    print("-------------------------")

# Отображение подключенных пользователей
    def show_connected_clients(self, iface: str, mac: str, timeout: int = 15):
        print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTCYAN_EX}Интерфейс: {Fore.GREEN}{iface}{Fore.LIGHTCYAN_EX}\nЦелевой MAC: {Fore.GREEN}{mac}{Fore.LIGHTCYAN_EX}\nТайм-аут: {Fore.GREEN}{timeout}\n")
        clients = self.sniff_ap_clients(ap_mac=mac, iface=iface, timeout=timeout)
        print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}»\n ---------------\n{Fore.LIGHTBLUE_EX}Всего обнаружено пользователей: {Fore.LIGHTGREEN_EX}{len(clients)}")
        for client in clients:
            print(client)

# Сканирование Wi-Fi трафика
    def sniff_wifi_traffic(self, iface: str, mac: str = None):
        def packet_handler(packet):
            if packet.haslayer(Dot11) and (mac is None or packet.addr3 == mac.lower()):
                print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» Обнаружен пакет: {Fore.LIGHTGREEN_EX}{packet.summary()}")

        print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.GREEN}Начало сканирования.... [CTRL + C для выхода]")
        try:
            sniff(prn=packet_handler, iface=iface, store=0)
        except Exception as e:
            print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Ошибка: {Fore.LIGHTRED_EX}{e}")

# Включение режима мониторинга
    def enable_monitor_mode(self, iface: str, mac: str = None):
        print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTCYAN_EX}Интерфейс: {Fore.GREEN}{iface}{Fore.LIGHTCYAN_EX}\nЦелевой MAC: {Fore.GREEN}{mac or 'Все точки доступа'}{Fore.LIGHTCYAN_EX}\n")
        print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Убедитесь, что указаны корректные данные и адаптер в режиме мониторинга.")
        self.sniff_wifi_traffic(iface=iface, mac=mac)

# Парсинг результатов сканирования
    def parse_results(self, text: str) -> list:
        networks = []
        for iface_result in text.strip().split("\n\n"):
            if not iface_result: continue
            info = {"iface": iface_result.split("\n")[0].split(" ")[0], "results": []}
            for net in iface_result.split("\n")[1:]:
                net = net.strip()
                if not net or net.startswith('Cell'): continue
                temp = {
                    "id": net.split()[1],
                    "ESSID": self.extract_value(net, "ESSID:"),
                    "channel": self.extract_value(net, "Channel:"),
                    "frequency": self.extract_value(net, "Frequency:"),
                    "signal_level": self.extract_value(net, "Signal level="),
                    "last_beacon": self.extract_value(net, "Last beacon:"),
                    "e_key": self.extract_value(net, "Encryption key:"),
                    "Secure": self.extract_value(net, "IEEE"),
                    "MAC": self.extract_value(net, "Address:")
                }
                info["results"].append(temp)
            networks.append(info)
        return networks

# Извлечение значения по ключу из строки
    def extract_value(self, text: str, key: str) -> str:
        if key in text:
            return text.split(key)[-1].strip().split()[0]
        return ""

# Парсинг аргументов командной строки
    def parse_args(self, args: list):
        if len(args) < 2:
            print(usage_info)
            return

        mode = args[1]
        if mode in ("-h", '--help'):
            print(usage_info)
        elif mode == '-n':
            self.show_networks_around()
        elif mode == '-uc':
            if len(args) < 4:
                print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Неправильные аргументы. Введите -h для справки")
                return
            iface, mac = args[2], args[3]
            timeout = int(args[4]) if len(args) > 4 else 30
            self.show_connected_clients(iface, mac, timeout)
        elif mode == '-m':
            if len(args) < 3:
                print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Неправильные аргументы. Введите -h для справки")
                return
            iface, mac = args[2], args[3] if len(args) > 3 else None
            self.enable_monitor_mode(iface, mac)
        else:
            print(usage_info)

# Основная функция программы
    def run(self):
        system('cls' if name == 'nt' else 'clear')
        print(program_logo)

        if name != 'nt' and geteuid() != 0:
            print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} Запустите программу с правами суперпользователя.")
            return
        elif name == 'nt':
            print(f"{Fore.LIGHTYELLOW_EX}[ {Fore.LIGHTRED_EX}GenWiFiScanner {Fore.LIGHTYELLOW_EX}] {Fore.LIGHTBLUE_EX}» {Fore.LIGHTYELLOW_EX} На Windows права суперпользователя не требуются.")
        
        self.parse_args(sys.argv)

if __name__ == "__main__":
    GenWiFiScanner().run()
