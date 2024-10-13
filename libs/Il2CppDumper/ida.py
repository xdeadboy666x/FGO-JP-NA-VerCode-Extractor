# -*- coding: utf-8 -*-
import json
import idaapi
import idc

processFields = [
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
]

imageBase = idaapi.get_imagebase()


def get_addr(addr):
    return imageBase + addr


def set_name(addr, name):
    ret = idc.set_name(addr, name, idc.SN_NOWARN | idc.SN_NOCHECK)
    if ret == 0:
        new_name = f"{name}_{addr:x}"  # Using hex formatting for clarity
        idc.set_name(addr, new_name, idc.SN_NOWARN | idc.SN_NOCHECK)


def make_function(start, end):
    next_func = idc.get_next_func(start)
    if next_func < end:
        end = next_func
    if idc.get_func_attr(start, idc.FUNCATTR_START) == start:
        idc.del_func(start)  # Corrected to use idc.del_func
    idc.add_func(start, end)


path = idaapi.ask_file(False, "*.json", "script.json from Il2cppdumper")

# Using context manager to read the JSON file
try:
    with open(path, "rb") as file:
        data = json.loads(file.read().decode("utf-8"))
except (IOError, json.JSONDecodeError) as e:
    print(f"Error reading JSON file: {e}")
    raise

if "Addresses" in data and "Addresses" in processFields:
    addresses = data["Addresses"]
    for index in range(len(addresses) - 1):
        start = get_addr(addresses[index])
        end = get_addr(addresses[index + 1])
        make_function(start, end)

if "ScriptMethod" in data and "ScriptMethod" in processFields:
    scriptMethods = data["ScriptMethod"]
    for scriptMethod in scriptMethods:
        addr = get_addr(scriptMethod["Address"])
        name = scriptMethod["Name"]  # No need to encode
        set_name(addr, name)

if "ScriptString" in data and "ScriptString" in processFields:
    index = 1
    scriptStrings = data["ScriptString"]
    for scriptString in scriptStrings:
        addr = get_addr(scriptString["Address"])
        value = scriptString["Value"]  # No need to encode
        name = f"StringLiteral_{index}"
        idc.set_name(addr, name, idc.SN_NOWARN)
        idc.set_cmt(addr, value, 1)
        index += 1

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
    scriptMetadatas = data["ScriptMetadata"]
    for scriptMetadata in scriptMetadatas:
        addr = get_addr(scriptMetadata["Address"])
        name = scriptMetadata["Name"]  # No need to encode
        set_name(addr, name)
        idc.set_cmt(addr, name, 1)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
    scriptMetadataMethods = data["ScriptMetadataMethod"]
    for scriptMetadataMethod in scriptMetadataMethods:
        addr = get_addr(scriptMetadataMethod["Address"])
        name = scriptMetadataMethod["Name"]  # No need to encode
        methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
        set_name(addr, name)
        idc.set_cmt(addr, name, 1)
        idc.set_cmt(addr, "{:X}".format(methodAddr), 0)

print("Script finished!")
