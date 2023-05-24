#TODO write a description for this script
#@author 
#@category Python 3
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

import ghidra

DEBUG = False

def getSigned(v):
    mask = 0x80 << ((v.getSize() - 1) * 8)
    value = v.getOffset()
    if value & mask:
        value -= 1 << (v.getSize() * 8)
    return value

def getDataTypeTraceBackward(v):
    res = v.getHigh().getDataType()
    p = v.getDef()
    if (p is not None) and (p.opcode == p.CAST):
        vn = p.getInput(0)
        f = ghidra.program.model.data.MetaDataType.getMostSpecificDataType
        res = f(res, vn.getHigh().getDataType())
    return res

def getDataTypeTraceForward(v):
    res = v.getHigh().getDataType()
    p = v.getLoneDescend()
    if (p is not None) and (p.opcode == p.CAST):
        vn = p.output
        f = ghidra.program.model.data.MetaDataType.getMostSpecificDataType
        res = f(res, vn.getHigh().getDataType())
    return res

def find_auto_structs(f):
    if isinstance(f, str):
        try:
            f = getGlobalFunctions(f)[0]
        except Exception:
            print("error: function '%s' not found." % f)
            return None
    opt = ghidra.app.decompiler.DecompileOptions()
    ifc = ghidra.app.decompiler.DecompInterface()
    #dut = ghidra.app.decompiler.component.DecompilerUtils
    ifc.setOptions(opt)
    ifc.openProgram(f.getProgram())
    Locs = {}
    try:
        res = ifc.decompileFunction(f, 1000, monitor)
        hf = res.getHighFunction()
        lsm = hf.getLocalSymbolMap()
    except AttributeError:
        return Locs
    for n, s in lsm.getNameToSymbolMap().items():
        S = []
        t = s.getDataType()
        if DEBUG:
            print("\nVariable name & type: '{}' : '{}'".format(n, t))
        if t.getDescription().startswith("pointer"):
            try:
                hv = s.getHighVariable()
                vn0 = hv.getRepresentative()
            except AttributeError:
                continue
            todo = [(vn0, 0)]
            done = list(hv.getInstances())
            for vn in done:
                if vn != vn0:
                    todo.append((vn, 0))
            while len(todo) > 0:
                if DEBUG:
                    print("todo: {}".format(todo))
                    print("done: {}".format(done))
                cur, off0 = todo.pop(0)
                if cur is None:
                    continue
                for p in cur.getDescendants():
                    off = off0
                    if DEBUG:
                        print("  pcode: {}".format(p))
                    if p.opcode == p.INT_ADD:
                        if p.inputs[1].isConstant():
                            off += getSigned(p.inputs[1])
                            if p.output not in done:
                                todo.append((p.output, off))
                                done.append(p.output)
                    elif p.opcode == p.INT_SUB:
                        if p.inputs[1].isConstant():
                            off -= getSigned(p.inputs[1])
                            if p.output not in done:
                                todo.append((p.output, off))
                                done.append(p.output)
                    elif p.opcode == p.PTRADD:
                        if p.inputs[1].isConstant() and p.inputs[2].isConstant():
                            off += getSigned(p.inputs[1]) * (
                                p.inputs[2].getOffset()
                            )
                            if p.output not in done:
                                todo.append((p.output, off))
                                done.append(p.output)
                    elif p.opcode == p.PTRSUB:
                        if p.inputs[1].isConstant():
                            off += getSigned(p.inputs[1])
                            if p.output not in done:
                                todo.append((p.output, off))
                                done.append(p.output)
                    elif p.opcode == p.LOAD:
                        outdt = getDataTypeTraceForward(p.output)
                        el = (off, outdt.getLength())
                        if el not in S:
                            S.append(el)
                    elif p.opcode == p.STORE:
                        if p.getSlot(cur) == 1:
                            outdt = getDataTypeTraceBackward(p.inputs[2])
                            el = (off, outdt.getLength())
                            if el not in S:
                                S.append(el)
                    elif p.opcode in (p.CAST, p.MULTIEQUAL, p.COPY):
                        if p.output not in done:
                            todo.append((p.output, off))
                            done.append(p.output)
                    if DEBUG:
                        print("S = {}".format(S))
            S.sort()
            Locs[n] = S
    return Locs

def find_functions_with_type(lref,nbfields=-1,sta=None,sto=None):
    fm = currentProgram.getFunctionManager()
    if nbfields==-1:
        nbfields = len(lref)
    sref = set(lref)
    F = []
    if sta:
        I = fm.getFunctionsNoStubs(toAddr(sta),True)
    else:
        I = fm.getFunctionsNoStubs(True)
    for f in I:
        if sto and not (f.getEntryPoint().getOffset() < sto):
            break
        if DEBUG:
            found=False
            print("%s... "%(f.getName()),end='')
        try:
            L = find_auto_structs(f)
        except:
            continue
        for k,l in L.items():
            if len(l)>=nbfields and set(l).issubset(sref):
                F.append((f,(k,l)))
                if DEBUG:
                    print("found.")
                    found=True
                break
        if DEBUG and not found:
            print("not found.")
    return F
