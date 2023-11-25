# wifi2qr

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A simple `bash` script to share your computer's WiFi connection settings
[via QR code](https://github.com/zxing/zxing/wiki/Barcode-Contents#wifi-network-config-android).

Requires the command-line utility
[`nmcli` from NetworkManager](https://developer.gnome.org/NetworkManager/stable/nmcli.html)—plus
[`qrencode`](https://fukuchi.org/works/qrencode/) and
[ImageMagick's `display`](https://www.imagemagick.org/script/display.php) in order to actually
display the barcode.

## Installation and usage

```sh
$ curl https://raw.githubusercontent.com/dlenski/wifi2qr/HEAD/wifi2qr > ~/bin/wifi2qr
$ chmod +x !$
$ wifi2qr
```

… which will display a barcode that you can read with your smartphone to connect to the
network. Tested with Android's `zxing`-based
[Barcode Scanner](https://play.google.com/store/apps/details?id=com.google.zxing.client.android),
the somewhat more modern
[QR & Barcode Scanner](https://f-droid.org/en/packages/com.example.barcodescanner),
and the iPhone Camera app.

![WIFI:S:ExampleWPA;T:WPA;P:ExamplePassword;;](example.png)

You can also share a specific connection, by its NetworkManager
connection name or UUID with `wifi2qr CONNECTION`.

You can list known WiFi connections with `wifi2qr -l`.

Note: **only** `zxing`-based apps appear to support [the E/A/I/PH2
fields which are needed to configure WPA-EAP ("Enterprise") WiFi
networks](https://github.com/zxing/zxing/wiki/Barcode-Contents#wi-fi-network-config-android-ios-11);
those fields are _not_ present in the official-ish
[WPA3 specification](https://www.wi-fi.org/system/files/WPA3%20Specification%20v3.1.pdf)
for WiFi URIs.

### Complete options

```
wifi2qr [-h] [-l] [-u | -a] [connection]

Displays a QR code that can be scanned to connect to a WiFi network
known to NetworkManager.

Options:
  connection    Show QR code for specific connection (if not
                specified, currently-enabled WiFi connection)
  -h            Show this help message
  -l            List WiFi connections known to NetworkManager
  -a | -i       Show QR code using ANSI characters or with ImageMagick
     | -o FILE  or save to a file (e.g. qrcode.png)
                (default is to show using UTF8 characters)
  -q            Quiet mode (default is to print barcode in text
                form to stderr as well; this suppresses it)
```
