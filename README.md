# malscan

malscan is a simple tool gluing YARA rules to Python scripts.

You write YARA rules to find whatever you want and scan the process memory with it. If a rule matches, it launches a Python script as specified in the rule file with information on where the match is.

Suppose you analyzed a malware and know how to locate its configuration block. You write a YARA rule to find the block, and a Python script to derypt it. malscan then scans the process memory for matches and runs your script on memory chunks that procuded a match.

## Usage example

Suppose we found out that some malware contains a config block starting with the bytes 0xAA 0xBB 0xCC 0xDD when in memory. The configuration is encrypted though.

Using malscan we can write a simple YARA rule:

```
rule malware_config_matcher
{
    meta:
        plugin = "extractor"
    strings:
        $config_start = { AA BB CC DD }
    condition:
        all of them
}
```

We then run malscan on an infected system, it scans all process memory for matches to this signature.

If a match is found, malscan will check if it should call plugin. Above we used YARA's meta information to define a plugin to be called on a match:

```
    meta:
        plugin = "extractor"
```

Malscan will then launch "extractor.py". In order to work as a plugin, it simply has to contain the following function:

```
# extractor.py
def on_match(info,data):
    ...
```

malscan will call `on_match()` when a rule matched and pass two arguments.

The first, `info`, is a dict like this:

```
{
	'address': 428343296,
	'matches':
		{
			'$config_start': (66212, 66233)
		},
	'pid': 5880,
	'executable': 'devenv.exe'
}
```

* `address` is the address of the memory chunk in the executable's memory space where the rule matched
* `pid` is the process ID of the process that contained the matching chunk
* `executable` is its name
* `matches` is a dict for every matching string from the YARA rule. Its value is a tuple of offsets in that memory chunk where the rule matched

And the 2nd argument to `on_match()` is `data`, which is the memory chunk itself.

With this data, extractor.py can easily decode the configuration as it has the memory chunk, and every location where the blob 0xAA 0xBB 0xCC 0xDD was found.

## Full example

We have a YARA file to locate the configuration:

```
rule malware_config_matcher
{
    meta:
        plugin = "extractor"
    strings:
        $config_start = { AA BB CC DD }
    condition:
        all of them
}
```

and a script to decrypt it:

```
# extractor.py

def on_match(info,data):
    if not "$config_start" in info["matches"]:
        # should not happen here because it's the only string
	# but if more strings are in the rule, it may not have produced
	# a match
        return
        
    for offset in info["matches"]["$config_start"]:
        #Assuming some fixed size
        config = data[offset:(offset+CONFIG_SIZE)]
        
        #And some function to decrypt that config
        plain = config_decrypt(config)
        
        print("Found config in %s, decrypted config = %s" % (info["executable"],plain))
```
