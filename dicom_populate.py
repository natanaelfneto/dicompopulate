from __future__ import print_function
import  argparse, datetime, os, time

# get current datetime
st = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")

# parse arguments from terminal
parser = argparse.ArgumentParser(description='a DCM4CHEE binaries usage with python scripting')
parser.add_argument('-p','--path', help='dicom folder path', required=True, default="check_string_for_empty")
parser.add_argument('-c','--pacs', help='ae title of destination PACS', required=True, default="check_string_for_empty")
parser.add_argument('-a','--address', help='ip address of destination PACS', required=True, default="check_string_for_empty")
parser.add_argument('-P','--port', help='port of destination PACS', required=True, default="check_string_for_empty")
parser.add_argument('-v','--verbose', action='store_true', help='process verbose flag', required=False)
parser.add_argument('-l','--log', action='store_true', help='save log file', required=False)
# add arguments on array
args = parser.parse_args()
log_instance = 0
log = "populate_"+str(log_instance)+".log"
dmc_log = "dcm.log"

# check log flag
if args.log:
    # check if log file already exist
    while os.path.isfile(os.getcwd()+"/"+log):
        log_instance = log_instance + 1
        log = "populate_"+str(log_instance)+".log"
    if not os.path.isfile(os.getcwd()+"/"+log):
        f = open(log,'w')
        f.write(st+" Starting log file\n")

ssh = args.pacs+"@"+args.address+":"+args.port
output = st+" Sending dicom files located at "+args.path+" to "+ssh

# check verbose flag
if args.verbose:
    print(output)
if args.log:
    f.write("\n"+output+"\n")

files = []
i = 0

# loop through folder
for root, dirs, files in os.walk(args.path):
    # check if folder is not empty
    if files:
        for file in files:
            # get absolute path
            file_path = os.path.abspath(os.path.join(root, file))
            # set command for dcm4chee binary
            command = "nohup sh ./dcm4chee-2.0.29/bin/dcmsnd "+ssh+" "+file_path+" </dev/null> "+dmc_log+" 2>&1 &"
            i = i + 1
            output = st+" Sending "+str(i)+": "+file_path
            if args.log:
                f.write(output+"\n")
            if args.verbose:
                print(output, end='\n')
            else:
                print(output, end='\r')
            # run the command
            os.system(command)
print("",end='\n')
if args.verbose:
    print("Log file merged. \n"+st+" "+"Process is now finished. \n The log file can be found at "+os.getcwd()+outlog)
# finish