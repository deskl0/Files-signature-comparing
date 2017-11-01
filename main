import sys
import os
import re
import time
import optparse
import sqlite3
import platform
import win32file
import win32con

global path
def browser(path):    
    if not os.path.isdir(path):
        return
    global filepath
    global db_data
    global filename,filenameFail,localTime,f,f1
    
    for i in range(1,30000):
        localTime = time.strftime("%Y-%m-%d %H.%M.%S",time.localtime())
        filename="./results/Known/"+localTime + ".txt"
        filenameFail="./results/Unknown/"+localTime + ".txt"
    db_data = read_database("signatures.sqlite")
    for root, dirs, list in os.walk(path):   
        for i in list:
            
            filepath = os.path.join(root, i)
            match_type(filepath)
            
            

def read_file(filepath):
    open_file = open(filepath, "rb")
    return "".join("{:02x}".format(int(ord(c))) for c in open_file.read(50))

def file_size(filepath):
    try:
        size = float(os.path.getsize(filepath))
        return_size = ""
        count = 0
        sizes = ["bytes", "KB", "MB", "GB", "TB"]
        while size > 1024:
            size /= 1024
            count += 1
        return_size = "{:0.2f} {}".format(size, sizes[count])
    except MemoryError:
        return_size = "Size too large"
    return return_size

def read_database(database_file):
    return_data = None
    try:
        con = sqlite3.connect(database_file)
        cur = con.cursor()
        cur.execute("SELECT * FROM signature")
        return_data = cur.fetchall()
    except sqlite3.Error, e:
        print "[-] ERROR : {}".format(e.args[0])
        sys.exit(1)
    finally:
        if con:
            con.close()
    return return_data
 
def hidden(filepath):
    if 'Windows' in platform.system():
        fileAttr = win32file.GetFileAttributes(filepath)
        if fileAttr & win32con.FILE_ATTRIBUTE_HIDDEN :
            return "True"
        return "False"
    return "False"

def match_type(filepath):
    file_data = read_file(filepath)
    mark = False
    #seq = 0
    sign_regex = []
    ext_regex = []
    count = 0
    for row in db_data:
        sign_regex.append(row[1])
        ext_regex.append(row[0])
    match_flag = False
    extension = ""
    description = ""
    status = ""
    file_split = filepath.split(".")
    ext = file_split[len(file_split) - 1]
    if db_data:
        for regex in sign_regex:
            sg_re = re.compile("^" + regex)
            if sg_re.search(file_data):
                match_flag = True
                if db_data[count][0] == "*":
                    description = db_data[count][2]
                    status = "File Extension Check Pass"
                    extension = ext
                    hide = hidden(filepath)
                    break
                else:
                    if str(db_data[count][0]).lower() == str(ext).lower():
                        description = db_data[count][2]
                        status = "File Extension Check Pass"
                        extension = ext
                        hide = hidden(filepath)
                        break
                    else:
                        
                        description = db_data[count][2]
                        status = "File Extension Check FAIL!"
                        extension = db_data[count][0]
                        hide = hidden(filepath)
                        mark = True
                        pass
            count += 1

    return_data = ""
    if match_flag:
        print ("[+] Found \n\tFilenanme : " + filepath + "\n\tSize : " + file_size(filepath) + "\n\tDescription : " + description + "\n\tReal Extension : ." + extension + "\n\tVerification : " + status + "\n\tHidden : " + hide)
        f=open(filename,'a')
        print >> f,filepath,"\t\t\t\t\tHidden: "+hide+"\n"+status+"\n"
        f.close()
        mark = False
    else:
        f1=open(filenameFail,'a')
        print >> f1,filepath,"\t\t\t\t\tHidden:"+hidden(filepath)+"\n"+status+"\n"
        f1.close()
        print ( "[-] Nothing known found\n\tFilenanme : " + filepath + "\n\tSize : " + file_size(filepath))
    
    return return_data

def main():
    optparser = optparse.OptionParser("%prog [options].\n\rThis script is used to analyse files for their extension changes.\n\r")
    optparser.add_option("-a", "", dest="filename", type="string", help="Target file")
    (options, args) = optparser.parse_args()

    if not options.filename:
        optparser.print_help()
        exit(True)
    else:
       browser(options.filename)

if __name__ == "__main__":
    main()
