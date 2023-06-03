import json
import re
import time
import datetime
import os

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.symbol import SourceType


"""
exec(open("/home/audit/Documents/R_CGW_SWEET400/script/AUTOSAR_rename/AUTOSAR_renameProto.py").read())
"""

ID_ADDR     = 0
ID_MODULE   = 1
PREFIX      = "auto_"

def det_functionIsInList(functionList, functionName):
    result = False
    for funcAddr in functionList:
        func = getFunctionAt(toAddr(funcAddr))
        if (func is not None) and (func.getName() in functionName):
            result = True
    return result


def det_functionIsRenamed(functionAddr):
    result = False
    func = getFunctionAt(toAddr(functionAddr))
    if (func is not None) and (not func.getName().startswith("FUN_")):
        result =  True
    return result


def det_functionExtractSubList(function, paramNumber):
    sublist = []
    for funcAddr in function:
        func = getFunctionAt(toAddr(funcAddr))
        if (func is not None) and (func.getParameterCount() == paramNumber) and (not det_functionIsRenamed(funcAddr)):
            sublist.append(funcAddr)
    return sublist


def det_setNameInfo(moduleId, serviceId , addrToComment, spec):
    listing     = currentProgram.getListing()
    codeUnit    = listing.getCodeUnitAt(addrToComment)
    func        = getFunctionContaining(addrToComment)

    if moduleId in spec:
        if serviceId in spec[moduleId]["services"]:
            detFunctionName     = spec[moduleId]["services"][serviceId]["name"]
            detFunctionParam    = int(spec[moduleId]["services"][serviceId]["param"])
            codeUnit.setComment(codeUnit.EOL_COMMENT,detFunctionName)
            callTraceList           = det_retreiveCallTrace(addrToComment)
            callTraceReducedList    = det_functionExtractSubList(callTraceList, detFunctionParam)
            if not det_functionIsInList(callTraceList, detFunctionName):
                if len(callTraceReducedList) == 1:
                    f1 = getFunctionAt(toAddr(callTraceReducedList[0]))
                    f1.setName(PREFIX + detFunctionName, SourceType.USER_DEFINED)
                    print("[Info][Rename] %d reduced to %d candidate(s) found "
                          "for %s # moduleId=%s, serviceId=%s" % (len(callTraceList),
                                                                  len(callTraceReducedList),
                                                                  addrToComment,
                                                                  moduleId,
                                                                  serviceId))
                elif len(callTraceList) == 1 and func.getName().startswith("FUN_"):
                    func.setName(PREFIX + detFunctionName + "?", SourceType.USER_DEFINED)
                    print("[Info][Rename][Proto] Only 1 candidate by prototype "
                          "not match for %s # moduleId=%s, serviceId=%s" % (addrToComment, moduleId, serviceId))
                else:
                    print("[Info][NOT][Rename] %d reduced to %d candidate(s) "
                          "found for %s # moduleId=%s, serviceId=%s" % (len(callTraceList),
                                                                        len(callTraceReducedList),
                                                                        addrToComment,
                                                                        moduleId,
                                                                        serviceId))
        else:
            codeUnit.setComment(codeUnit.EOL_COMMENT,spec[moduleId]["abbreviation"])
            print("[Warning] Unknown 'serviceId' "
                  "at %s # moduleId=%02x, serviceId=%02x" % (addrToComment, int(moduleId), int(serviceId)))
    else:
        print("[Warning] Unknown 'moduleId' "
              "at %s # moduleId=%02x, serviceId=%02x" % (addrToComment, int(moduleId), int(serviceId)))


def buildAST(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    ifc.setSimplificationStyle("normalize")
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high


def det_retreiveCallTrace(addrReference):
    functionList    = []
    bbVisited       = []
    bbToVisit       = []
    func = getFunctionContaining(addrReference)
    if func is None:
        return functionList
    functionList.append(func.getEntryPoint().toString())
    high = buildAST(func)
    opiter = high.getPcodeOps()
    while opiter.hasNext():
        node = opiter.next()
        if node.getMnemonic() == "CALL" and node.getParent().contains(addrReference):
            for i in range(node.getParent().getInSize()):
                bbToVisit.append(node.getParent().getIn(i))
                bbVisited.append(node.getParent().getIn(i).toString())
            while len(bbToVisit) != 0:
                pblock = bbToVisit.pop(0)
                for op in pblock.getIterator():
                    if op.getMnemonic() == "CALL":
                        if op.getInput(0).getAddress() not in functionList:
                            functionList.append(op.getInput(0).getAddress().toString())
                for i in range(pblock.getInSize()):
                    if pblock.getIn(i).toString() not in bbVisited:
                        bbVisited.append(pblock.getIn(i).toString())
                        bbToVisit.append(pblock.getIn(i))
    return functionList


def det_retreiveFunctionName(addrReference, detFunctionAddr, spec):
    func = getFunctionContaining(addrReference)
    found = False
    if func is not None:
        high = buildAST(func)
        opiter = high.getPcodeOps()
        while opiter.hasNext() and not found:
            node = opiter.next()
            if node.getMnemonic() == "CALL" \
                    and node.getParent().contains(addrReference) \
                    and node.getInput(0).getAddress() == toAddr(detFunctionAddr):
                param1 = node.getInput(1)
                param3 = node.getInput(3)
                found = True
                if param1 is not None and param3 is not None and param1.isConstant() and param3.isConstant():
                    p1 = param1.getOffset() 
                    p3 = param3.getOffset() 
                    det_setNameInfo(str(p1), str(p3), node.getInput(0).getPCAddress(), spec)
                else:
                    print("[Error] Parsing error %s" % node.getInput(0).getPCAddress().toString())
    if not found:
        print("[Warning] Cross reference not found %s" % addrReference.toString())


def det_retreiveSubFunctionName(addrReference, detFunctionAddr, moduleId, spec):
    func = getFunctionContaining(addrReference)
    found = False
    if func is not None:
        high = buildAST(func)
        opiter = high.getPcodeOps()
        while opiter.hasNext() and not found:
            node = opiter.next()
            if node.getMnemonic() == "CALL" and node.getParent().contains(addrReference) and node.getInput(0).getAddress() ==  toAddr(detFunctionAddr):
                param1 = node.getInput(1)
                found = True
                if param1 != None and param1.isConstant():
                    p1 = parseInt(param1.toString())
                    det_setNameInfo(str(moduleId), str(p1), node.getInput(0).getPCAddress(), spec)
                else:
                    print("[Error] Parsing error %s " % node.getInput(0).getPCAddress().toString())
    if found:
        print("[Warning] Cross reference not found %s " % addrReference.toString())


def det_rename(jsonFile, detFuncList, detSubFuncList):
    if not os.path.isfile(jsonFile):
        print("[Info] Problem with jsonFile")
        return
    with open(jsonFile) as f:
        spec = json.load(f)
        for detFunctionAddr in detFuncList:
            references = getReferencesTo(toAddr(detFunctionAddr))
            for xref in references:
                func = getFunctionContaining(xref.getFromAddress())
                if func is None:
                    print("[Info] Function not defined %s" % xref.getFromAddress())
                else:
                    det_retreiveFunctionName(xref.getFromAddress(), detFunctionAddr, spec)
        for subfunc in detSubFuncList :
            references = getReferencesTo(toAddr(subfunc[0]))
            for xref in references:
                func = getFunctionContaining(xref.getFromAddress())
                if func is None:
                    print("[Info] Function not defined %s " % xref.getFromAddress())
                else:
                    det_retreiveSubFunctionName(xref.getFromAddress(), subfunc[ID_ADDR], subfunc[ID_MODULE], spec)

if __name__ == '__main__':
    begintime = time.time()
    jsonFile        = "~/AUTOSAR_rename/AUTOSAR-4.4.json"
    detFuncList     = [0x80098678, 0x806496da]
    detSubFuncList  = [[0x800a05fc,  10]]
    det_rename(jsonFile, detFuncList, detSubFuncList)
    print("[Info] Finish in %s" % str(datetime.timedelta(seconds = time.time() - begintime)))
