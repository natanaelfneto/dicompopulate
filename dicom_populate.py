
from __future__ import print_function
import  argparse, datetime, os, time

st = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S")

parser = argparse.ArgumentParser(description='A DCM4CHEE usage with python script')
parser.add_argument('-p','--path', help='DICOM folder path', required=True, default="check_string_for_empty")
parser.add_argument('-c','--pacs', help='AE Title of destination PACS', required=True, default="check_string_for_empty")
parser.add_argument('-a','--address', help='IP address of destination PACS', required=True, default="check_string_for_empty")
parser.add_argument('-P','--port', help='Port of destination PACS', required=True, default="check_string_for_empty")
parser.add_argument('-v','--verbose', action='store_true', help='Process verbose flag', required=False)
parser.add_argument('-l','--log', action='store_true', help='Save log file', required=False)
args = parser.parse_args()

if args.log:
    if os.path.isfile(os.getcwd()+"/dicom_populate.log"):
        f = open('dicom_populate.log','a')
    else:
        f = open('dicom_populate.log','w')
        f.write(st+" Starting log file\n")

ssh = args.pacs+"@"+args.address+":"+args.port
output = st+" Sending dicom files located at "+args.path+" to "+ssh
if args.verbose:
    print(output)
if args.log:
    f.write("\n"+output+"\n")

files = []
i = 0
count = sum([len(files) for r, d, files in os.walk(args.path)])

for root, dirs, files in os.walk(args.path):
    if files:
        for file in files:
            file_path = os.path.abspath(os.path.join(root, file))
            command = "sh ./dcm4chee-2.0.29/bin/dcmsnd "+ssh+" "+file_path
            i = i+1
            percent = round(100*(float(i)/float(count)),2)
            output = " %"+" completed. Sending "+file_path+", "+str(i)+" out of "+str(count)+" files"
            if args.log:
                f.write("{0:.2f}".format(percent)+output+"\n")
            if args.verbose:
                print(st+" "+"{0:.2f}".format(percent)+output, end='\n')
            else:
                print(st+" "+"{0:.2f}".format(percent)+output, end='\r')
            os.system(command)
if args.verbose:
    print("",end='\n')
    print(st+" "+"Finished. \n The log file output can be found at "+os.getcwd()+"/dicom_populate.log.")
