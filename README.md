# EN
**GenWiFiScanner** is a Python-based tool designed for monitoring WiFi networks and users. It allows users to scan nearby WiFi networks, view connected devices, and analyze traffic. This tool is useful for network administrators and enthusiasts who want to understand their wireless environment.

## Features
- **Network Scanning**: Discover nearby WiFi networks and display detailed information.
- **User Detection**: Identify and list devices connected to a specific access point.
- **Traffic Monitoring**: Capture and display WiFi traffic for analysis.
- **Cross-Platform Support**: Compatible with Windows and Unix-based systems (Linux, macOS).

## Requirements
- A WiFi adapter capable of monitor mode.
- Python 3.x installed on your system.
- `scapy` and `colorama` Python packages.

## Installation
1. **Clone the repository**:
    ```bash
    git clone https://github.com/geniuszly/GenWiFiScanner.git
    cd GenWiFiScanner
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. **Basic Commands**:
    - Scan for nearby networks:
      ```bash
      python GenWiFiScanner.py -n
      ```
    - Show users connected to an access point:
      ```bash
      python GenWiFiScanner.py -uc <interface> <AP_MAC>
      ```
    - Monitor WiFi traffic:
      ```bash
      python GenWiFiScanner.py -m <interface> [<AP_MAC>]
      ```

2. **Example**:
    - To view users connected to an access point:
      ```bash
      python GenWiFiScanner.py -uc wlan0mon 00:1A:2B:3C:4D:5E 60
      ```

## Important Notes
- **Permissions**: On Unix systems, root privileges are required to use monitor mode.

## Disclaimer 
- This tool is intended for educational purposes only. The author is not responsible for any misuse of this tool.


# RU
**GenWiFiScanner** - это инструмент на основе Python, предназначенный для мониторинга WiFi сетей и пользователей. Он позволяет сканировать ближайшие сети WiFi, просматривать подключенные устройства и анализировать трафик. Этот инструмент полезен для сетевых администраторов и энтузиастов, которые хотят понять свою беспроводную среду.

## Возможности
- **Сканирование сетей**: Обнаружение ближайших WiFi сетей и отображение подробной информации.
- **Обнаружение пользователей**: Идентификация и список устройств, подключенных к определенной точке доступа.
- **Мониторинг трафика**: Захват и отображение WiFi трафика для анализа.
- **Кросс-платформенная поддержка**: Совместимость с Windows и Unix-системами (Linux, macOS).

## Требования
- WiFi адаптер с поддержкой режима мониторинга.
- Установленный Python 3.x.
- Пакеты Python `scapy` и `colorama`.

## Установка
1. **Клонируйте репозиторий**:
    ```bash
    git clone https://github.com/geniuszly/GenWiFiScanner.git
    cd GenWiFiScanner
    ```

2. **Установите зависимости**:
    ```bash
    pip install -r requirements.txt
    ```

## Использование
1. **Основные команды**:
    - Сканирование ближайших сетей:
      ```bash
      python GenWiFiScanner.py -n
      ```
    - Просмотр пользователей, подключенных к точке доступа:
      ```bash
      python GenWiFiScanner.py -uc <интерфейс> <MAC_адрес_ТД>
      ```
    - Мониторинг WiFi трафика:
      ```bash
      python GenWiFiScanner.py -m <интерфейс> [<MAC_адрес_ТД>]
      ```

2. **Пример**:
    - Для просмотра пользователей, подключенных к точке доступа:
      ```bash
      python GenWiFiScanner.py -uc wlan0mon 00:1A:2B:3C:4D:5E 60
      ```

## ВАЖНО
- **Права доступа**: В Unix-системах для использования режима мониторинга требуются права суперпользователя.

## Отказ от ответственности 
Этот инструмент предназначен только для образовательных целей. Автор не несет ответственности за любое неправомерное использование этого инструмента.
