# -*- coding: utf-8 -*-
import json
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

processFields = [
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
USER_DEFINED = ghidra.program.model.symbol.SourceType.USER_DEFINED


def get_addr(addr):
    return baseAddress.add(addr)


def set_name(addr, name):
    try:
        name = name.replace(" ", "-")
        createLabel(addr, name, True, USER_DEFINED)
    except Exception as e:
        print(f"set_name() Failed: {e}")


def set_type(addr, type_str):
    newType = type_str.replace("*", " *").replace("  ", " ").strip()
    dataTypes = getDataTypes(newType)
    addrType = None
    if len(dataTypes) == 0:
        if newType == newType[:-2] + " *":
            baseType = newType[:-2]
            dataTypes = getDataTypes(baseType)
            if len(dataTypes) == 1:
                dtm = currentProgram.getDataTypeManager()
                pointerType = dtm.getPointer(dataTypes[0])
                addrType = dtm.addDataType(pointerType, None)
    elif len(dataTypes) > 1:
        print(
            f"Conflicting data types found for type {type_str} (parsed as '{newType}')"
        )
        return
    else:
        addrType = dataTypes[0]

    if addrType is None:
        print(f"Could not identify type {type_str} (parsed as '{newType}')")
    else:
        try:
            createData(addr, addrType)
        except ghidra.program.model.util.CodeUnitInsertionException:
            print("Warning: unable to set type (CodeUnitInsertionException)")


def make_function(start):
    func = getFunctionAt(start)
    if func is None:
        try:
            createFunction(start, None)
        except Exception as e:
            print(f"Warning: Unable to create function: {e}")


def set_sig(addr, name, sig):
    try:
        typeSig = CParserUtils.parseSignature(None, currentProgram, sig, False)
    except ghidra.app.util.cparser.C.ParseException:
        print("Warning: Unable to parse signature")
        print(sig)
        print("Attempting to modify...")
        # try to fix by renaming the parameters
        try:
            newSig = sig.replace(", ", " ext, ").replace(")", " ext)")
            typeSig = CParserUtils.parseSignature(None, currentProgram, newSig, False)
        except Exception as e:
            print(f"Warning: also unable to parse: {newSig} - {e}")
            return

    if typeSig is not None:
        try:
            typeSig.setName(name)
            ApplyFunctionSignatureCmd(addr, typeSig, USER_DEFINED, False, True).applyTo(
                currentProgram
            )
        except Exception as e:
            print(
                f"Warning: unable to set Signature. ApplyFunctionSignatureCmd() Failed: {e}"
            )


# Open JSON file using a context manager
f = askFile("script.json from Il2cppdumper", "Open")
with open(f.absolutePath, "rb") as file:
    data = json.loads(file.read().decode("utf-8"))

if "ScriptMethod" in data and "ScriptMethod" in processFields:
    scriptMethods = data["ScriptMethod"]
    monitor.initialize(len(scriptMethods))
    monitor.setMessage("Processing Methods")
    for scriptMethod in scriptMethods:
        addr = get_addr(scriptMethod["Address"])
        name = scriptMethod["Name"]
        set_name(addr, name)
        sig = scriptMethod["Signature"][:-1]  # Assuming this is intentional
        set_sig(addr, name, sig)
        monitor.incrementProgress(1)

if "ScriptString" in data and "ScriptString" in processFields:
    index = 1
    scriptStrings = data["ScriptString"]
    monitor.initialize(len(scriptStrings))
    monitor.setMessage("Processing Strings")
    for scriptString in scriptStrings:
        addr = get_addr(scriptString["Address"])
        value = scriptString["Value"]
        name = f"StringLiteral_{index}"
        createLabel(addr, name, True, USER_DEFINED)
        setEOLComment(addr, value)
        index += 1
        monitor.incrementProgress(1)

if "ScriptMetadata" in data and "ScriptMetadata" in processFields:
    scriptMetadatas = data["ScriptMetadata"]
    monitor.initialize(len(scriptMetadatas))
    monitor.setMessage("Processing Metadata")
    for scriptMetadata in scriptMetadatas:
        addr = get_addr(scriptMetadata["Address"])
        name = scriptMetadata["Name"]
        set_name(addr, name)
        setEOLComment(addr, name)
        monitor.incrementProgress(1)
        if "Signature" in scriptMetadata and scriptMetadata["Signature"]:
            set_type(addr, scriptMetadata["Signature"])

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
    scriptMetadataMethods = data["ScriptMetadataMethod"]
    monitor.initialize(len(scriptMetadataMethods))
    monitor.setMessage("Processing Metadata Methods")
    for scriptMetadataMethod in scriptMetadataMethods:
        addr = get_addr(scriptMetadataMethod["Address"])
        name = scriptMetadataMethod["Name"]
        methodAddr = get_addr(scriptMetadataMethod["MethodAddress"])
        set_name(addr, name)
        setEOLComment(addr, name)
        monitor.incrementProgress(1)

if "Addresses" in data and "Addresses" in processFields:
    addresses = data["Addresses"]
    monitor.initialize(len(addresses))
    monitor.setMessage("Processing Addresses")
    for index in range(len(addresses) - 1):
        start = get_addr(addresses[index])
        make_function(start)
        monitor.incrementProgress(1)

print("Script finished!")
