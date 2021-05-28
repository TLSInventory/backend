#!/bin/bash

with open("version.txt", "r+") as f:
    version = f.read().split(".")
    final_string = f"{version[0]}.{int(version[1])+1}.{version[2]}"
    f.seek(0)
    f.truncate()  # truncate requires cursor at the beginning of the file
    f.write(final_string)
