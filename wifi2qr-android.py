#!/usr/bin/env python3

import argparse
from sys import stderr
from binascii import hexlify, unhexlify, a2b_base64
import struct
from os.path import splitext
import tempfile
import shlex
from xml.etree import ElementTree as ET
from dataclasses import dataclass
from hashlib import pbkdf2_hmac
from typing import Union, Optional

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
_WCSSA_PATHS = (
    '/data/misc/wifi/WifiConfigStoreSoftAp.xml',                       # ?
    '/data/misc/apexdata/com.android.wifi/WifiConfigStoreSoftAp.xml',  # ?
)


p = argparse.ArgumentParser(description=
    'Displays a QR code that can be scanned to connect to a WiFi network '
    'known to your Android device (which must be connected via ADB and '
    'must allow ADB root access).')
p.add_argument('-d', '--device', help='ADB serial number of device to connect to (default is first connected device)')
x = p.add_mutually_exclusive_group()
x.add_argument('-l', '--list', action='store_true')
x.add_argument('connection', nargs='?', help='Android ConfigKey name or SSID for WiFi connection')
x.add_argument('--hotspot', action='store_true', help="Fetch WiFi hotspot configuration from Android device")
x = p.add_mutually_exclusive_group()
x.add_argument('-a', '--ansi', dest='display', default='UTF8', action='store_const', const='ANSI')
x.add_argument('-i', '--ImageMagick', dest='display', action='store_const', const='ImageMagick')
x.add_argument('-o', '--output', type=argparse.FileType('wb'))
p.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (suppress printing of barcode in text form to stderr)')
p.add_argument('-P', '--psk', action='store_true', help='Scramble plaintext WPA2 passwords into hexadecimal pre-shared keys')
args = p.parse_args()

cli = ppadb.client.Client()
try:
    cli.create_connection()
except RuntimeError:
    p.error("Error connecting to local ADB server (try 'adb connect IP[:PORT]' or 'adb mdns services' to find devices on local network).")

if args.device:
    device = cli.device(args.device)
elif cli.devices():
    device = cli.devices()[0]
    if not args.quiet:
        print(f'Connected to Android device {device.serial}.', file=stderr)
else:
    p.error("No currently connected Android device (try 'adb connect IP[:PORT]' or 'adb mdns services' to find devices on local network).")

use_su = False
try:
    device.root()
    if not args.quiet:
        print('Received ADB root access to device.', file=stderr)
except RuntimeError as exc:
    if exc.args[0] == 'adbd is already running as root':
        if not args.quiet:
            print('Already have ADB root access to device.', file=stderr)
    else:
        if int(device.shell('su -c true; echo $?').splitlines()[-1]) == 0:
            use_su = True
            if not args.quiet:
                print("Couldn't enable ADBD as root, but can use 'su' (see https://stackoverflow.com/a/28070414)", file=stderr)
        else:
            p.error('Could not get ADB root access to device.')

def raw_and_maybe_text(raw: Union[bytes, str, None]) -> tuple[Optional[bytes], Optional[str]]:
    if raw is None:
        # None -> None, None
        return None, None
    elif isinstance(raw, bytes):
        try:
            # b'foo' -> b'foo', 'foo'
            return raw, raw.decode('utf8')
        except ValueError:
            # b'\xf0\x00' -> b'\xf00\x00', 'f000'
            return raw, hexlify(raw).decode()
    elif raw[:1] == '"' and raw[-1:] == '"':
        # '"foo"' -> b'foo', 'foo'
        t = raw[1:-1]
        return t.encode('utf8'), t
    else:
        try:
            # 'f00f' -> b'\xf0\x0f', 'f00f'
            return unhexlify(raw), raw
        except ValueError:
            # 'foo' -> b'foo', 'foo'
            return raw.encode('utf8'), raw

assert raw_and_maybe_text(b'foo') == (b'foo', 'foo')
assert raw_and_maybe_text(b'\xf0\x00') == (b'\xf0\x00', 'f000')
assert raw_and_maybe_text('"foo"') == (b'foo', 'foo')
assert raw_and_maybe_text('f00f') == (b'\xf0\x0f', 'f00f')
assert raw_and_maybe_text('foo') == (b'foo', 'foo')

@dataclass
class EAP:
    client_cert: Optional[str]
    password: Optional[str]
    anon_identity: Optional[str]
    identity: Optional[str]
    method: Optional[str]
    phase2_method: Optional[str]

@dataclass
class WifiNetwork:
    configkey: str
    ssid: Union[str, bytes]
    ssid_t: str
    psk: Union[str, bytes, None] = None
    psk_t: Optional[str] = None
    eap: Optional[EAP] = None
    connected: bool = False
    broken: bool = False
    hidden: bool = False
    timestamp: Optional[int] = None

    @classmethod
    def munge_xml_ap(cls, nn):
        ssid, ssid_t = raw_and_maybe_text(nn.findtext("SoftAp/string[@name='WifiSsid']"))
        psk, psk_t = raw_and_maybe_text(nn.findtext("SoftAp/string[@name='Passphrase']"))
        hidden = nn.find("SoftAp/boolean[@name='HiddenSSID']")
        if hidden is not None:
            hidden = (hidden.attrib.get('value', 'false') == 'true')

        return cls(configkey='Android hotspot', hidden=hidden, ssid=ssid, ssid_t=ssid_t, psk=psk, psk_t=psk_t)
    
    @classmethod
    def munge_xml(cls, nn):
        status = nn.find("WifiConfiguration/int[@name='Status']")
        connected = broken = None

        via = nn.find("WifiConfiguration/boolean[@name='ValidatedInternetAccess']")
        hec = nn.find("NetworkStatus/boolean[@name='HasEverConnected']")
        if via is not None:
            broken = (via.attrib.get('value', 'false') == 'false')
        elif hec is not None:
            broken = (hec.attrib.get('value', 'false') == 'false')

        if status is not None:
            val = int(status.attrib.get('value', '1'))
            connected = (val == 0)
            broken = (val == 1)

        hidden = nn.find("WifiConfiguration/boolean[@name='HiddenSSID']")
        if hidden is not None:
            hidden = (hidden.attrib.get('value', 'false') == 'true')

        timestamp = nn.find("NetworkStatus/long[@name='ConnectChoiceTimeStamp']")
        if timestamp is not None:
            val = int(timestamp.attrib.get('value', '-1'))
            timestamp = val if val != -1 else None

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
            connected=connected, broken=broken, hidden=hidden, timestamp=timestamp,
            ssid=ssid, ssid_t=ssid_t,
            psk=psk, psk_t=psk_t,
            eap=eap,
        )

    
def get_hotspot(device):
    with tempfile.NamedTemporaryFile(prefix='WifiConfigStoreSoftAp_', suffix='.xml') as tf:
        for path in _WCSSA_PATHS:
            if use_su:
                *lines, res = device.shell(f"set -o pipefail; su -c cat {shlex.quote(path)} | base64; echo $?").splitlines()
                if int(res) == 0:
                    err = None
                    tf.writelines(a2b_base64(l) for l in lines)
                else:
                    err = res
            else:
                err = device.pull(path, tf.name)
            if err is None:
                mtime = int(device.shell(f"su -c date -r {shlex.quote(path)} +%s")) * 1000
                tf.seek(0)
                xml = ET.parse(tf)

                n = WifiNetwork.munge_xml_ap(xml)
                n.timestamp = mtime
                return n

    with tempfile.NamedTemporaryFile(prefix='softap_', suffix='.conf', mode='w+b') as tf:
        path = '/data/misc/wifi/softap.conf'
        if use_su:
            *lines, res = device.shell(f"set -o pipefail; su -c cat {shlex.quote(path)} | base64; echo $?").splitlines()
            if int(res) == 0:
                err = None
                tf.writelines(a2b_base64(l) for l in lines)
            else:
                err = res
        else:
            err = device.pull(path, tf.name)
        if err:
            raise RuntimeError(f"Error pulling softap.conf from device: {err}")
        tf.seek(0)
        contents = tf.read()
        mtime = int(device.shell(f"su -c date -r {shlex.quote(path)} +%s")) * 1000
        
        n = get_hotspot_old(path, contents)
        n.timestamp = mtime
        return n

    raise RuntimeError(f"Error pulling WifiConfigStoreSoftAp.xml or softap.conf from device: {err}")


def get_hotspot_old(path, contents):
    # Newer versions of Android have apparently moved this to the WifiConfigStore.xml:
    # https://android.googlesource.com/platform/frameworks/base/+/master/wifi/java/src/android/net/wifi/SoftApConfToXmlMigrationUtil.java#111
    version, ssid_len = struct.unpack_from('>IH', contents, 0)
    assert 1 <= version <= 3
    if not args.quiet:
        print(f"Pulled {path} from Android device (softap.conf v{version})")

    ssid, = struct.unpack_from(f'>{ssid_len}s', contents, pos := 6)
    pos += ssid_len
    hidden = band = channel = psk = None
    if version >= 2:
        band, channel = struct.unpack_from('>2I', contents, pos)
        pos += 8
        if version >= 3:
            hidden, = struct.unpack_from('>?', contents, pos)
            pos += 1

    auth_type, = struct.unpack_from('>I', contents, pos)
    pos += 4
    assert auth_type in (0, 4)  # None, WPA2_PSK (https://developer.android.com/reference/android/net/wifi/WifiConfiguration.KeyMgmt#WPA2_PSK)
    if auth_type == 4:
        psk_len, = struct.unpack_from('>H', contents, pos)
        pos += 2
        psk, = struct.unpack_from(f'>{psk_len}s', contents, pos)
        pos += psk_len
    assert pos == len(contents)

    ssid, ssid_t = raw_and_maybe_text(ssid)
    psk, psk_t = raw_and_maybe_text(psk)
    return WifiNetwork(
        configkey='Android hotspot', ssid=ssid, ssid_t=ssid_t, psk=psk, psk_t=psk_t)

def get_wcs(device):
    with tempfile.NamedTemporaryFile(prefix='WifiConfigStore_', suffix='.xml') as tf:
        for path in _WCS_PATHS:
            if use_su:
                *lines, res = device.shell(f"set -o pipefail; su -c cat {shlex.quote(path)} | base64; echo $?").splitlines()
                if int(res) == 0:
                    err = None
                    tf.writelines(a2b_base64(l) for l in lines)
                else:
                    err = res
            else:
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
        return sorted(
            (WifiNetwork.munge_xml(nn) for nn in xml.findall('./NetworkList/Network')),
            key=lambda nn: (not nn.connected, nn.broken,
                            nn.ssid_t, nn.configkey))

if args.list:
    networks = get_wcs(device)
    try:
        networks.insert(0, get_hotspot(device))
    except RuntimeError:
        pass

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

if args.hotspot:
    try:
        nn = get_hotspot(device)
    except RuntimeError as exc:
        p.error(f"Could not determine Android device's WiFi hotspot configuration: {exc.args[0]}")
elif not args.connection:
    # Get the [first] active connection
    networks = get_wcs(device)
    nn = next((nn for nn in networks if nn.connected), None)
    if nn:
        print(f'Using currently-active WiFi connection from Android device {nn.configkey}')
    else:
        p.error('Could not find a currently-active WiFi connection on Android device')
else:
    networks = get_wcs(device)
    nn = next((nn for nn in networks if args.connection in (nn.ssid_t, nn.configkey)), None)
    if nn:
        if not args.quiet:
            print(f'Using WiFi connection {nn.configkey} from Android device...', file=stderr)
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
    if len(nn.psk_t) < 64 and args.psk:
        psk_t = pbkdf2_hmac('sha1', nn.psk, nn.ssid, 4096, 32).hex()  # http://jorisvr.nl/wpapsk.html
    else:
        psk_t = nn.psk_t   # already PSK-ified, or no PSK
    bits.update(T='WPA', P=psk_t)
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
