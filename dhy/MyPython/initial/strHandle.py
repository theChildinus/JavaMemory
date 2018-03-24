#*coding=utf-8
import re
import ConfigParser
file_conf = ConfigParser.ConfigParser()
with open("./src/main.objdump",'r') as f:
    objdump_str = f.read()

file_conf.read("./src/main.conf")
sections_list = file_conf.sections()
sections_dict = {}

for func in sections_list:
    paranum = file_conf.get(func, "ParaNum")
    paratype = file_conf.get(func, "ParaType")
    parasize = file_conf.get(func, "ParaSize")
    para_list = [paranum,paratype,parasize]
    sections_dict[func] = para_list

print sections_dict

        
#the initial range  "libc  ---  main " 
start_index = objdump_str.find("<__libc_start_main@plt>:")
end_index =  objdump_str.find("<__libc_csu_fini>:")
objdump_str = objdump_str[start_index:end_index]
#print total_str

pattern0 = re.compile(r"<.*>:")
pattern1 = re.compile(r"call.*<.*>") #function call
pattern2 = re.compile(r"[a-zA-Z0-9]*:")   #return_address

func_list = re.findall(pattern0, objdump_str)
call_iter = re.finditer(pattern1, objdump_str) #迭代 用一次就没有了！！！！！！！！！！
#for func_str in func_list:
#    print func_str[1:-2]

handle_dict = {}
#string handle ---> dict
handle_str = objdump_str
for call_str in call_iter:
    call_string = call_str.group()
    #narrow  range    
    call_index = handle_str.index(call_string)
    handle_str = handle_str[(call_index + len(call_string)):]
    return_address = re.search(pattern2,handle_str)
    #test = re.search(pattern2, handle_str).span()
    #print test
    #print handle_str[130:140]
    #if return_address.group(0) in "0:":
        #print handle_str
    handle_dict[return_address.group()[:-1]] = call_string
print handle_dict

