#!/bin/python3

import argparse
from sys import stderr
from binascii import hexlify, unhexlify
from os.path import splitext
import tempfile
from xml.etree import ElementTree as ET
from dataclasses import dataclass

import ppadb.client
from qrcode import QRCode

# Based on my own analysis of the WiFiConfigStore.xml
# https://blog.digital-forensics.it/2024/02/dissecting-android-wificonfigstorexml.html
# I later found another project that munges this file:
# https://github.com/mnalis/android-wifi-upgrade/blob/master/convert_wifi.pl
# To reload this file we need to stop and restart wifi on the device, something like this:
# adb shell "nohup sh -c 'svc wifi disable; sleep 3; svc wifi enable' > /dev/null 2>&1"

# TODO: Use zeroconf to browse for devices advertising "_adb._tcp.local.", and
# automatically connect.
# https://github.com/python-zeroconf/python-zeroconf?tab=readme-ov-file#how-do-i-use-it

def _escape(s: str):
    return ''.join('\\'+c if c in r'\";:,' else c for c in s)

def wifi_uri(**bits):
    return 'WIFI:' + ';'.join(f'{k}:{_escape(v)}' for k, v in bits.items()) + ';;'

# https://developer.android.com/reference/android/net/wifi/WifiEnterpriseConfig.Eap
_EAP_METHODS = {5: 'AKA', 6: 'AKA_PRIME', 0xffffffff: 'NONE', 0: 'PEAP', 3: 'PWD', 4: 'SIM', 1: 'TLS', 2: 'TTLS', 7: 'UNAUTH_TLS', 8: 'WAPI_CERT'}
# https://developer.android.com/reference/android/net/wifi/WifiEnterpriseConfig.Phase2
_EAP_PHASE2_METHODS = {0: 'NONE', 3: 'MSCHAPV2'} # ...
# https://github.com/NeoApplications/Neo-Backup/blob/672dd22879c674aada640a4618fffd2f070d64a4/app/src/main/java/com/machiav3lli/backup/dbs/entity/SpecialInfo.kt#L192
_WCS_PATHS = (
    '/data/misc/wifi/WifiConfigStore.xml',                       # Android O (8.0)+
    '/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml',  # Android R (11.0)+
)

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
    'known to your Android device (which must be connected via ADB and '
    'must allow ADB root access).')
p.add_argument('-d', '--device', help='ADB serial number of device to connect to (default is first connected device)')
x = p.add_mutually_exclusive_group()
x.add_argument('-l', '--list', action='store_true')
x.add_argument('connection', nargs='?', help='Android ConfigKey name or SSID for WiFi connection')
x = p.add_mutually_exclusive_group()
x.add_argument('-a', '--ansi', dest='display', default='UTF8', action='store_const', const='ANSI')
x.add_argument('-i', '--ImageMagick', dest='display', action='store_const', const='ImageMagick')
x.add_argument('-o', '--output', type=argparse.FileType('wb'))
p.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (suppress printing of barcode in text form to stderr)')
args = p.parse_args()

cli = ppadb.client.Client()
try:
    cli.create_connection()
except RuntimeError as exc:
    p.error("Error connecting to local ADB server (try 'adb connect IP[:PORT]' or 'adb mdns services' to find devices on local network).")

if args.device:
    device = cli.device(args.device)
elif cli.devices():
    device = cli.devices()[0]
    if not args.quiet:
        print(f'Connected to Android device {device.serial}.', file=stderr)
else:
    p.error("No currently connected Android device (try 'adb connect IP[:PORT]' or 'adb mdns services' to find devices on local network).")

try:
    device.root()
    if not args.quiet:
        print('Received ADB root access to device.', file=stderr)
except RuntimeError as exc:
    if exc.args[0] == 'adbd is already running as root':
        if not args.quiet:
            print('Already have ADB root access to device.', file=stderr)
    else:
        raise

def raw_and_maybe_text(raw):
    if raw is None:
        return None, None
    elif raw[:1] == '"' and raw[-1:] == '"':
        r = t = raw[1:-1]
    else:
        try:
            r = unhexlify(raw)
            t = r.decode('utf8')
        except ValueError:
            r = t = raw
    return r, t

@dataclass
class EAP:
    client_cert: str | None
    password: str | None
    anon_identity: str | None
    identity: str | None
    method: str | None
    phase2_method: str | None

@dataclass
class WifiNetwork:
    configkey: str
    ssid: str | bytes
    ssid_t: str
    psk: str | bytes | None = None
    psk_t: str | None = None
    eap: EAP | None = None
    connected: bool = False
    broken: bool = False
    hidden: bool = False

    @classmethod
    def munge_xml(cls, nn):
        status = nn.find("WifiConfiguration/int[@name='Status']")
        hec = nn.find("NetworkStatus/boolean[@name='HasEverConnected']")
        if status is not None:
            connected = (int(status.attrib.get('value', '1')) == 0)
            broken = (int(status.attrib.get('value', '1')) == 1)
        elif hec is not None:
            connected = False
            broken = (hec.attrib.get('value', 'false') == 'false')
        else:
            connected = False
            broken = True

        hidden = nn.find("WifiConfiguration/boolean[@name='HiddenSSID']")
        if hidden is not None:
            hidden = (hidden.attrib.get('value', 'false') == 'true')

        configkey = nn.findtext("WifiConfiguration/string[@name='ConfigKey']")

        eap = nn.find('WifiEnterpriseConfiguration')
        if eap is not None:
            client_cert = eap.findtext("./string[@name='ClientCert']")
            identity = eap.findtext("./string[@name='Identity']")
            anon_identity = eap.findtext("./string[@name='AnonIdentity']")
            password = eap.findtext("./string[@name='Password']")

            method = eap.find("./int[@name='EapMethod']")
            if method is not None:
                method = _EAP_METHODS.get(int(method.attrib.get('value', '0')))
            phase2_method = eap.find("./int[@name='Phase2Method']")
            if phase2_method is not None:
                phase2_method = _EAP_PHASE2_METHODS.get(int(phase2_method.attrib.get('value', '0')))

            eap=EAP(
                client_cert=client_cert, identity=identity, anon_identity=anon_identity,
                password=password, method=method, phase2_method=phase2_method)

        ssid, ssid_t = raw_and_maybe_text(nn.findtext("WifiConfiguration/string[@name='SSID']"))
        psk, psk_t = raw_and_maybe_text(nn.findtext("WifiConfiguration/string[@name='PreSharedKey']"))

        return cls(
            configkey=configkey,
            connected=connected, broken=broken, hidden=hidden,
            ssid=ssid, ssid_t=ssid_t,
            psk=psk, psk_t=psk_t,
            eap=eap,
        )

with tempfile.NamedTemporaryFile(prefix='WifiConfigStore_', suffix='.xml') as tf:
    for path in _WCS_PATHS:
        err = device.pull(path, tf.name)
        if err is None:
            break
    else:
        raise RuntimeError(f"Error pulling WifiConfigStore.xml from device: {err}")
    tf.seek(0)
    xml = ET.parse(tf)

    version = xml.find("./int[@name='Version']")
    if version is not None:
        version = version.attrib.get('value')
    if not args.quiet:
        print(f"Pulled {path} from Android device (WifiConfigStore v{version})")
    networks=sorted(
        [WifiNetwork.munge_xml(nn) for nn in xml.findall('./NetworkList/Network')],
        key=lambda nn: (not nn.connected, nn.broken, nn.ssid_t, nn.configkey))

if args.list:
    print('Known WiFi connections:', file=stderr)
    for nn in networks:
        if nn.eap:
            sec = 'WPA-EAP'
        elif nn.psk:
            sec = 'WPA-PSK'
        else:
            sec = 'open'

        print(f'  [{sec:8s}] SSID {nn.ssid_t:34} (Android ConfigKey name: {nn.configkey})', file=stderr)
    p.exit(1)

if not args.connection:
    # Get the [first] active connection
    if networks and networks[0].connected:
        nn = networks[0]
        print(f'Using currently-active WiFi connection from Android device {nn.configkey}')
    else:
        p.error('Could not find a currently-active WiFi connection on Android device')
else:
    for nn in networks:
        if args.connection in (nn.ssid_t, nn.configkey):
            if not args.quiet:
                print(f'Using WiFi connection {nn.configkey} from Android device...', file=stderr)
            break
    else:
        p.error(f'Could not find WiFi connection on Android device with ConfigKey or SSID of {args.connection!r}')

bits = dict(S=nn.ssid_t)
if nn.hidden:
    bits['H'] = 'true'

if nn.eap:
    #raise RuntimeError
    # These EAP-related settings appear to be ZXing-specific extensions. See
    # https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11
    if nn.eap.client_cert:
        p.error('cannot generate QR code for an EAP network using client certificates')
    if not nn.eap.password:
        p.error('cannot generate QR code for an EAP network without a password')
    bits.update(T='WPA2-EAP', P=nn.eap.password, E=nn.eap.method.upper())
    if nn.eap.anon_identity:
        bits['A'] = nn.eap.anon_identity
    if nn.eap.identity:
        bits['I'] = nn.eap.identity
    if nn.eap.phase2_method:
        bits['PH2'] = nn.eap.phase2_method.upper()
elif nn.psk:
    bits.update(T='WPA', P=nn.psk_t)
    #if ws.get('key-mgmt') == 'sae':
    #    # WPA2/WPA3 transition disable
    #    # See https://superuser.com/a/1752085 and https://www.wi-fi.org/system/files/WPA3%20Specification%20v3.1.pdf secetion 7
    #    bits['R'] = '1';

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
