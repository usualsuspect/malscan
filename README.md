# malscan

malscan is a tool to scan process memory for YARA matches and execute Python scripts if a match is found.

This is useful for extracting configurations from malware process memory for example.

## Real world example

We want to extract PoisonIvy configurations. From reverse engineering, we know that the configuration blob starts with "\x08\x00StubPath" in memory inside a PoisonIvy process.

So we write a YARA rule to detect configurations:

```YARA
rule pi_config
{
    meta:
        plugin = "pi_config_extract"
    strings:
        $config_start = "\\x08\\x00StubPath"
    condition:
        all of them
}
```

In the meta information, we tell `malscan` what plugin to run if this rule matches.

The plugin is quite simple:

```Python
import io
import struct

def word(fh):
    return struct.unpack("<H",fh.read(2))[0]

def on_match(info,data):
    print("Found PoisonIvy config in %s" % info["executable"])
    for off in info["matches"]["$config_start"]:
        off -= 2

        fh = io.BytesIO(data[off:])

        while True:
            coff = word(fh)
            if coff == 0:
                break
            size = word(fh)
            cdata = fh.read(size)

            print("    %03x %04d %s" % (coff,size,repr(cdata)))
```

`malscan` will call `on_match()` when the rule above matched. It passes some meta information (see below) and the memory chunk itself where the rule matched.

Our script then simply parses the PoisonIvy configuration blob using that information.

Example output:

```
C:\Documents and Settings\user\Desktop\malscan>malscan.exe
Loading plugin pi_config_extract
Loading rule rules\pi_config.yara
Found PoisonIvy config in poison.exe
    40f 0008 b'StubPath'
    418 0040 b'SOFTWARE\\Classes\\http\\shell\\open\\command'
    456 0053 b'Software\\Microsoft\\Active Setup\\Installed Components\\'
    afa 0007 b'testing'
    190 0016 b'\x0c192.168.56.1\x00\x84\r'
    18c 0004 b'\x00\x00\x00\x00'
    2c1 0004 b'\xff\xff\xff\xff'
    145 0005 b'admin'
    3fb 0009 b')!VoqA.I4'
Press any key to continue . . .
```

## Using malscan

`malscan` expects two directories:

* `plugins` with \*.py files
* `rules` with YARA rule files

You also MUST have Python 3.4 x86 installed on the system you want to scan on. There's multiple reasons:

* Python 3.6 has no support for Windows XP and malscan is supposed to run on Windows XP, hence 3.4
* `malscan` does not come with Python because plugins most likely will require additional packages (e.g. for crypto), and embedded Python does not support using of `pip` or the likes to install packages

Therefore, the target system must come with a proper Python distribution itself.

Other than that nothing else is required. `malscan` should run on everything from XP to Win10 as long as Python 3.4 x86 is installed.

## Details

The `info` dict passed to `on_match` contains the following information:

```
{
    "address": 428343296,
    "matches":
        {
            "$config_start": (66212, 66233)
        },
    "pid": 5880,
    "executable": 'pi.exe'
}
```

* `address` is the address of the memory chunk in the scanned process
* `matches` contains a list of offsets for every matched YARA identifier
* `pid` is the process ID
* `executable` is the process' name

And the 2nd argument, `data` is simply the memory chunk where the rule matched. Offsets in the `matches` dict inside `info` are relative to this chunk.
