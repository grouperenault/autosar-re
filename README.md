 # Introduction

This ghidra script renames some AUTOSAR functions by exploiting information provided by the DET module. 

# How to use it? 

Copy scripts in the ghidra python console (or put it in the ghidrai\_script folder)

``` 
jsonFile       = "/../AUTOSAR_rename/AUTOSAR-4.4.json" 
detFuncList    = [0x80098678, 0x8009869a] # list containing Det_repportError function address 
detSubFuncList = [[0x800a05fc, 10]] # list containing Macro Det_repportError associated with a ModuleId, this argument is not mandatory and can be replaced with an empty list 
det_rename(jsonFile, detFuncList, detSubFuncList)  

""" 
@80098678: Std_ReturnType Det_ReportError (uint16 ModuleId, uint8 InstanceId, uint8 ApiId, uint8 ErrorId) 
{ ... } 

@800a05fc: Std_ReturnType Det_ReportError_Module10 ( uint8 ErrorId) { 
Det_ReportError(10,InstanceId, ApiId, ErrorId) 
} 
""" 
``` 

# How it works? 

This method is presented during the SSTIC conference (https://www.sstic.org/2023/presentation/Retro-ingenierie_de_systemes_embarques_AUTOSAR/). AUTOSAR standard defines some functions that should be implemented for each module. Each function is described with a specific prototype and is identified by a couple (ModuleID, serviceID). For example, _TcpIp\_TcpListen_ function has prototype "Std\_ReturnType TcpIp\_TcpListen(TcpIp\_SocketIdType SocketId, uint16 MaxChannels )" and is identified by _ModuleID=170_ and _serviceID=0x07_. 
For each _det\_repport_error_ function call, the script :    
- Parse _det\_repport_ arguments call to identify the _ModuleID_ and the _ServiceID_    
- Identify the AUTOSAR function associated to the _ModuleID_ and _ServiceID_    
- Rename the function associated to AUTOSAR function (by looking at a function having the same header inside the call stack) 

# Environment 

This script was tested with the Ghidra version (10.3 2023-jan-23).
