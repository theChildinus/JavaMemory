#    get information form *.c and *.objdump
#    make a dict of initial program
#      2015.11.23
#    dhy
import sys
import re
class InfoProgram(object):
    """information form *.objdump"""

    #call 4004c4
    #ret  (400527)   judge which region returnaddress(ret)  belongs to   
    ObjdumpDict = {0x4004c4:"func1"}
    
    
    
    """information form *.c"""
    FunctionNum = 3
    
    FunctionName = ["func1","func2","func3"]
    
    NumDict = {"func1":2,
               "func2":5,
               "func3":3
                   }
    
    FunctionDict = {"func1":
                        ["long int","float"],
                    "func2":
                        ["float","long int","float","long int","long int"],
                    "func3":
                        ["long int","int","char"]}
    
    
    TypeSizeDict = {"long int":8,
                    "int":4,
                    "float":4,
                    "double":8,
                    "char":1}
    
    
    pattern = re.compile(r"[0-9a-z]+ <.*>:")   

    def __init__(self):
        self.objfilepath = ""
        self.start_read_offset_address = None
        self.analyze_count = None
        self.funcaddr_list = []
        self.funcname_list = []
        
    def GetAnalyzeCount(self):
        self.analyze_count = 1
        
    def GetReadOffsetAddr(self):
        #mou zhong fang shi  que ding  pian yi di zhi 
        self.start_read_offset_address = 0x400
        
    
    def GetInfoFormOBJ(self):
        """objdump -D -M intel main > main.objdump  in the virtual machine"""
        
        self.objfilepath = "/initial/src/main.objdump" 
        
        try: 
            with open(self.objfilepath,'r') as pf:
                objdump_str = pf.read()
        except IOError:
            print "Failed to read objdump file!"
            sys.exit()
            

        obj_list = re.findall(self.pattern, objdump_str)
        #print obj_list
        for func_str in obj_list:
            func_list = func_str.split(" ",1)
            
            self.funcaddr_list.append(func_list[0][-6:])    #4004c4
            self.funcname_list.append(func_list[1][1:-2])    #func1
            
        #print funcaddr_list
        #print funcname_list
        
#t = InfoProgram()
#t.GetInfoFormOBJ()
#print t.ObjdumpDict
        
        