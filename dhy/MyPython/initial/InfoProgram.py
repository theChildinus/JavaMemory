#    get information form *.c and *.objdump
#    make a dict of initial program
#      2015.11.23
#    dhy
import sys
import re
import os
import volatility.debug as debug
class InfoProgram(object):
    """information form *.objdump"""

    #call 4004c4
    #ret  (400527)   judge which region returnaddress(ret)  belongs to   

    
    
    
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
    
    
    #pattern = re.compile(r"[0-9a-z]+ <.*>:")   
    start_read_offset_address = None
    def __init__(self,exa):
        self.objfilepath = ""

        self.analyze_count = None
        
        #self.funcaddr_list = []
        #self.funcname_list = []
        
        self.objdump_str = exa
        print self.objdump_str

        
    def GetAnalyzeCount(self):
        self.analyze_count = 10
        
    def GetReadOffsetAddr(self):
        #mou zhong fang shi  que ding  pian yi di zhi 
        self.start_read_offset_address = 0x4000
        
    
    def GetInfoFormOBJ(self):
        """objdump -D -M intel main > main.objdump  in the virtual machine"""
        """print "GetInfoFormOBJ"
        #self.objfilepath = r"./initial/src/main.objdump" 
        filepath = os.path.join(os.path.abspath(self.objfilepath),"/objfile/main.objdump")
        if os.path.exists(filepath):
            debug.info("file exists:{}".format(filepath))
        
        try: 
            with open(filepath,'r') as pf:
                objdump_str = pf.read()
                print "right"
        except IOError:
            print "Failed to read objdump file!"
            sys.exit()"""
            
        obj_list = re.findall(self.pattern, self.objdump_str)
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
        
        