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

# check log flag
if args.log:
    # check if log file already exist
    if os.path.isfile(os.getcwd()+"/dicom_populate.log"):
        f = open('dicom_populate.log','a')
    else:
        f = open('dicom_populate.log','w')
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

# get all dicom files count
count = sum([len(files) for r, d, files in os.walk(args.path)])

# loop through folder
for root, dirs, files in os.walk(args.path):
    # check if folder is not empty
    if files:
        for file in files:
            # get absolute path
            file_path = os.path.abspath(os.path.join(root, file))
            # set command for dcm4chee binary
            command = "sh ./dcm4chee-2.0.29/bin/dcmsnd "+ssh+" "+file_path
            i = i+1
            # get percentage
            percent = round(100*(float(i)/float(count)),2)
            output = " %"+" completed. Sending "+file_path+", "+str(i)+" out of "+str(count)+" files"
            if args.log:
                f.write("{0:.2f}".format(percent)+output+"\n")
            if args.verbose:
                print(st+" "+"{0:.2f}".format(percent)+output, end='\n')
            else:
                print(st+" "+"{0:.2f}".format(percent)+output, end='\r')
            # run the command
            os.system(command)
if args.verbose:
    print("",end='\n')
    print(st+" "+"Finished. \n The log file can be found at "+os.getcwd()+"/dicom_populate.log.")
# finish