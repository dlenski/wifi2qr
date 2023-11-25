#!/bin/python3

import argparse
from subprocess import check_output
from sys import stderr
from binascii import hexlify
from qrcode import QRCode
from os.path import splitext

def _escape(s: str):
    return ''.join('\\'+c if c in r'\";:,' else c for c in s)

def wifi_uri(**bits):
    return 'WIFI:' + ';'.join(f'{k}:{_escape(v)}' for k, v in bits.items()) + ';;'

_NMCLI = 'nmcli'
_SECMAP = {'wpa-psk': 'WPA-PSK', 'wpa-eap': 'WPA-EAP', 'sae': 'WPA3-SAE', None: 'open'}

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
x.add_argument('connection', nargs='?', help='NetworkManager connection name or UUID for WiFi connection')
x = p.add_mutually_exclusive_group()
x.add_argument('-a', '--ansi', dest='display', default='UTF8', action='store_const', const='ANSI')
x.add_argument('-i', '--ImageMagick', dest='display', action='store_const', const='ImageMagick')
x.add_argument('-o', '--output', type=argparse.FileType('wb'))
p.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (suppress printing of barcode in text form to stderr)')
args = p.parse_args()

if args.list:
    print('Known WiFi connections:', file=stderr)
    for uuid, (name, type) in nmcli_tf(['uuid', 'name', 'type'], 'conn'):
        if type == "802-11-wireless":
            sec = dict(nmcli_tf(['802-11-wireless-security.key-mgmt'], 'conn', 'show', uuid)).get('802-11-wireless-security.key-mgmt')
            print(f'  {name} ({_SECMAP.get(sec, sec)})', file=stderr)
    p.exit(1)

conn = args.connection
if not conn:
    try:
        conn, cname = next(
            (uuid, name) for uuid, (name, type) in nmcli_tf(['uuid', 'name', 'type'], 'conn', 'show', '--active')
            if type == '802-11-wireless'
        )
    except StopIteration:
        p.error('no WiFi connection active; specify connection name')
    else:
        print(f'Using current WiFi connection {cname!r} ...', file=stderr)

parms = dict(
    nmcli_tf(['connection.type',
             '802-11-wireless.ssid',
             '802-11-wireless.hidden',
             '802-11-wireless-security.psk',
             '802-11-wireless-security.key-mgmt',
             '802-1x.eap',
             '802-1x.anonymous-identity',
             '802-1x.identity',
             '802-1x.phase2-auth',
             '802-1x.password'],
             '-s', 'conn', 'show', conn)
)

if parms['connection.type'] != '802-11-wireless':
    p.error(f'connection {conn!r} is {parms["connection.type"]}, not WiFi')
if not parms.get('802-11-wireless.ssid'):
    p.error('could not interpret nmcli output')

bits = dict(S=parms["802-11-wireless.ssid"])
if parms.get('802-11-wireless.hidden') == 'yes':
    bits['H'] = 'true'
if parms.get('802-11-wireless-security.key-mgmt') == 'sae':
    # WPA2/WPA3 transition disable
    # See https://superuser.com/a/1752085 and https://www.wi-fi.org/system/files/WPA3%20Specification%20v3.1.pdf secetion 7
    bits['R'] = '1';

if parms.get('802-1x.eap'):
    # These EAP-related settings appear to be ZXing-specific extensions. See
    # https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11
    assert parms.get('802-1x.password')
    bits.update(T='WPA2-EAP', P=parms["802-1x.password"], E=parms["802-1x.eap"].upper())
    if parms.get('802-1x.anonymous-identity'):
        bits['A'] = parms["802-1x.anonymous-identity"]
    if parms.get('802-1x.identity'):
        bits['I'] = parms["802-1x.identity"]
    if parms.get('802-1x.phase2-auth'):
        bits['PH2'] = parms["802-1x.phase2-auth"].upper()
elif parms.get('802-11-wireless-security.psk'):
    bits.update(T='WPA', P=parms["802-11-wireless-security.psk"])

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
