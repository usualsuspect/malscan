# malscan

malscan is a simple tool gluing YARA rules to Python scripts.

You write YARA rules to find whatever you want and scan the process memory with it. If a rule matches, it launches a Python script as specified in the rule file with information on where the match is.

Suppose you analyzed a malware and know how to locate its configuration block. You write a YARA rule to find the block, and a Python script to derypt it. malscan then scans the process memory for matches and runs your script on memory chunks that procuded a match.



