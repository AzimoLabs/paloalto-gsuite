# GlobalProtect for Linux

## Description

This project allow Linux machines connect to VPN using openconnect.

## Required
- python3
- openconnect

### Fedora 29

```
sudo dnf install openconnect-8.02-2.fc29.x86_64
```

### DebilUntu

```
apt-get install openconnect
```

## Installation

First we have to install all dependence in Python3
```
pip3 install --user -r requirements.txt
```

## Configuration

Please edit file `gp-gsuite.conf` and change settings:
- `vpn_url` if address change, by default `https://vpn.azimo.com`
- `username` your gmail account, ex. `pawel.szmuc@azimo.com`
- `password` leave empty, I don't want know your password
- `gateway` not used at this moment, by default `Manual vpn.azimo.com`
- `webdriver` path to binnary `chromedrive` (at this moment we are using chromedrive in version 73)
- `webdriver_dir` where all cookies should be saved, by default  `~/.azimo.gp`
- `openconnect_cmd` if you don't have to use root privillages can be empty
- `prelogin_cookie` if you already know `prelogin_cookie` you can skip cookie generation
- `openconnect_args` extra parameters for openconnect
- `execute` 1 or true to execute, 0 for debug only
- `debug` 1 or true for debug variables
- `bug.nl` 1 or true, newline work-around for openconnect
- `bug.username` 1 or true, username work-around for openconnect

## Usage

It's verrryyyyyy easy :)
```
./gp-gsuite.py <conf>
```

Example:
```
./gp-gsuite.py gp-gsuite.conf
```

## Issues
1. chromedrive cache (java kur12)
```
selenium.common.exceptions.WebDriverException: Message: unknown error: Chrome failed to start: exited abnormally
  (unknown error: DevToolsActivePort file doesn't exist)
  (The process started from chrome location /usr/bin/google-chrome is no longer running, so ChromeDriver is assuming that Chrome has crashed.)
  (Driver info: chromedriver=73.0.3683.68 (47787ec04b6e38e22703e856e101e840b65afe72),platform=Linux 5.0.5-200.fc29.x86_64 x86_64)
```
Solution:
```
rm -rf /tmp/.com.google.Chrome*
```
