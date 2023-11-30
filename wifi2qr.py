#!/bin/python3

import argparse
from sys import stderr
from binascii import hexlify
from os.path import splitext

import pydbus
from qrcode import QRCode

def _escape(s: str):
    return ''.join('\\'+c if c in r'\";:,' else c for c in s)

def wifi_uri(**bits):
    return 'WIFI:' + ';'.join(f'{k}:{_escape(v)}' for k, v in bits.items()) + ';;'

_SECMAP = {'wpa-psk': 'WPA-PSK', 'wpa-eap': 'WPA-EAP', 'sae': 'WPA3-SAE', None: 'open'}
_DBUS_NM = 'org.freedesktop.NetworkManager'
_DBUS_NM_SLASH = '/org/freedesktop/NetworkManager'
_DBUS_NM_S_SLASH = '/org/freedesktop/NetworkManager/Settings'

def nmcli_tf(fields, *args):
    args = [_NMCLI, '-t', '-f', ','.join(fields), *args]
    for line in check_output(args, text=True).splitlines():
        vals = line.split(':')
        if len(vals) == 2:
            yield vals[0], vals[1]
        else:
            yield vals[0], vals[1:]

p = argparse.ArgumentParser(description=
    'Displays a QR code that can be scanned to connect to a WiFi network '
    'known to NetworkManager.')
x = p.add_mutually_exclusive_group()
x.add_argument('-l', '--list', action='store_true')
x.add_argument('connection', nargs='?', help='NetworkManager connection name or UUID or SSID for WiFi connection')
x = p.add_mutually_exclusive_group()
x.add_argument('-a', '--ansi', dest='display', default='UTF8', action='store_const', const='ANSI')
x.add_argument('-i', '--ImageMagick', dest='display', action='store_const', const='ImageMagick')
x.add_argument('-o', '--output', type=argparse.FileType('wb'))
p.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (suppress printing of barcode in text form to stderr)')
args = p.parse_args()

bus = pydbus.SystemBus()
settings = bus.get(_DBUS_NM, _DBUS_NM_S_SLASH)

if args.list:
    print('Known WiFi connections:', file=stderr)
    for path in settings.ListConnections():
        sc = bus.get(_DBUS_NM, path)
        config = sc.GetSettings()
        name = config['connection']['id']
        uuid = config['connection']['uuid']
        ssid = None
        if config['connection']['type'] == '802-11-wireless':
            sec = config.get('802-11-wireless-security', {}).get('key-mgmt')
            ssid = bytes(config['802-11-wireless']['ssid'])
            try:
                ssid_t = repr(ssid.decode())
            except UnicodeDecodeError:
                ssid_t = hexlify(ssid).decode()
            print(f'  [{_SECMAP.get(sec, sec):8s}] SSID {ssid_t:34} (NetworkManager name: {name})', file=stderr)
    p.exit(1)

if not args.connection:
    # Get the Dbus paths of the active connections
    mgr = bus.get(_DBUS_NM, _DBUS_NM_SLASH)
    apaths = { bus.get(_DBUS_NM, p).Connection for p in mgr.ActiveConnections }

for path in settings.ListConnections():
    sc = bus.get(_DBUS_NM, path)
    config = sc.GetSettings()
    name = config['connection']['id']
    uuid = config['connection']['uuid']
    ssid = None
    if config['connection']['type'] == '802-11-wireless':
        ssid = bytes(config['802-11-wireless']['ssid'])
        try:
            ssid_t = ssid.decode()
        except UnicodeDecodeError:
            ssid_t = None

        if not args.connection and path in apaths:
            if not args.quiet:
                print(f'Using currently-active WiFi connection {name!r} ...', file=stderr)
            break
        elif args.connection in (uuid, name, ssid_t):
            if not args.quiet:
                print(f'Using WiFi connection {name!r} ...', file=stderr)
            break
else:
    if args.connection:
        p.error(f'Could not find NetworkManager WiFi connection with UUID/name/SSID of {args.connection!r}')
    else:
        p.error(f'Could not find a currently-active NetworkManager WiFi connection')

w, ws, eap = config['802-11-wireless'], config.get('802-11-wireless-security', {}), config.get('802-1x', {})
bits = dict(S=bytes(w['ssid']).decode())  # FIXME: non-UTF8 SSID?
if w.get('hidden') == 'yes':
    bits['H'] = 'true'

if eap:
    # These EAP-related settings appear to be ZXing-specific extensions. See
    # https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11
    if eap.get('client-cert'):
        p.error('cannot generate QR code for an EAP network using client certificates')
    pwd = sc.GetSecrets('802-1x')['802-1x'].get('password')
    if not pwd:
        p.error('cannot generate QR code for an EAP network without a password')
    bits.update(T='WPA2-EAP', P=pwd, E=eap['eap'][0].upper())
    if eap.get('anonymous-identity'):
        bits['A'] = eap['anonymous-identity']
    if eap.get('identity'):
        bits['I'] = eap['identity']
    if eap.get('phase2-auth'):
        bits['PH2'] = eap['phase2-auth'].upper()
elif ws:
    psk = sc.GetSecrets('802-11-wireless-security')['802-11-wireless-security'].get('psk')
    if psk:
        bits.update(T='WPA', P=psk)
    if ws.get('key-mgmt') == 'sae':
        # WPA2/WPA3 transition disable
        # See https://superuser.com/a/1752085 and https://www.wi-fi.org/system/files/WPA3%20Specification%20v3.1.pdf secetion 7
        bits['R'] = '1';

uri = wifi_uri(**bits)
q = QRCode()
q.add_data(uri)
if args.output:
    q.make_image().save(args.output, (splitext(args.output.name)[1][1:].upper() or 'PNG'))
elif args.display == 'ANSI':
    q.print_tty()
elif args.display == 'UTF8':
    q.print_ascii(invert=True)
else:
    p.error(f'mode {args.display} not supported')

if not args.quiet:
    print(uri, file=stderr)
