#!/usr/bin/env python

# project name
__project__ = "populate"

# project version
__version__ = "0.5"

# prohect author
__author__ = "natanaelfneto"
__authoremail__ = "natanaelfneto@outlook.com"

# project source code
__source__ = "https://github.com/natanaelfneto/dicom_populate"

# project general description
__description__ = '''
This DICOM Populate module:

is a Script to populate a PACS with folder of DICOM files

# Author - Natanael F. Neto <natanaelfneto@outlook.com>
# Source - https://github.com/natanaelfneto/dicom_populate
'''

# project short description
short_description = "a script to populate a PACS with folder of DICOM files"

# third party imports
import argparse
import datetime
import getpass
import logging
import pydicom
import os
import re
import sys
import time

from pydicom import read_file
from pydicom.uid import ImplicitVRLittleEndian
from pynetdicom3 import AE
from pynetdicom3 import StoragePresentationContexts

'''
    In runtime there will be some global variables available

    * logger, wich contains an instance for logging with stream and file handles
        to be used across classes and functions
    
    * associations, with consist of an array of Association instancies wich each
        object has an open association with the remote application entity
'''

# class for populate application entities
class Populate(object): 

    # initialize an instance
    def __init__(self, paths):
        ''' 
            Initiate a DICOM Populate instance.

            Argument:
                logger: a logging instance for output and log
        '''

        # setup logger
        self.logger = logger.adapter
        self.verbose = logger.verbose
        self.paths = paths
        self.file_counter = 0

    # enter class basic rotine
    def __enter__(self):
        '''
            Function for entering class with python 3 standards of
            'with' parameter and a following __exit__ function for
            a cleanner use of the class instancies
        '''
        try:
            return self
        except StopIteration:
           raise RuntimeError("Instance could not be returned")

    # send helper for send function
    def send_helper(self, file_path):
        '''
            Function to send each file parsed in send() function on the loop
            that checks for files or directories and its subdirectories and files
        '''

        # status standard value
        status = False
    
        try:
            # check if file can be parsed as dicom
            dcmfile = pydicom.dcmread(file_path, force=True)
            status = True
            self.verbose("Successfully parsed {0} as a DICOM file".format(file_path))

        # exception on parse file as a dicom valid formatted file
        except Exception as e:
            self.logger.error("Could not parse {0} as a DICOM file".format(file_path))

        if status:
            # send file to each available connection
            for association in associations:

                # increment file counter
                self.file_counter = self.file_counter + 1

                # output message
                output = "File No. {0}, AE: {1}, IP: {2}, PORT: {3}, PATH: {4}".format(
                    str(self.file_counter),
                    association.title,
                    association.addr,
                    association.port,
                    file_path
                )

                self.logger.debug("Trying C-STORE of {0}".format(output))

                # try to send file through the dicom protocol within C-STORE
                try:
                    # call C-STORE function
                    association.store(file_path)

                    # check if file was successfully sent to application entity
                    if True:
                        # log successfully file transmition on verbose flag
                        if logger.verbose_flag:
                            self.verbose(output)
                        else:
                            print("==>> {0} <<==".format(output), end='\r')
                    else:
                        self.logger.debug("{0} could not be sent".format(output))

                # exception parser on sending file through the dicom protocol
                except Exception as e:
                    self.logger.error("Error while sending {0} ERROR: {1}".format(output, e))
   
    # function to send each valid dicom file to each valid application entity connection
    def send(self):
        '''
            DICOM Populate send function. Get all files inside received paths and
            send then to PACS environments with especific connections also received
            from function call

            Arguments:
                files: Array of files and/or folder to be sent to a PACS environment
                connection: Parameters for sending DICOM files
                    connection.aet: Application Entity Title, the PACS 'given name'
                    connection.addr: short for address, the IP Address of the server wich is runnig
                    connection.port: usually 11112 for dicom comunication, but customable
        '''

        # loop through folder
        self.logger.info('Looking for files, folder and its subfolders...')
        for path in self.paths:

            # log message
            self.logger.debug('Looking for files, folders and its subfolders at {0}...'.format(path))

            # check if path is a file
            if os.path.isfile(path):
                
                # send file to parsed connections
                self.send_helper(os.path.abspath(path))

            # else path is not a file but a directory
            else:
                self.logger.debug('Checking for files inside {0}'.format(path))    

                # get files inside current path
                for root, dirs, files in os.walk(path):
                    # check if folder is not empty

                    if files:
                        # for each file founded
                        for file in files:

                            # get absolute path
                            file_path = os.path.abspath(os.path.join(root, file))

                            # send file to parsed connections
                            self.send_helper(file_path)

                    # if no files were found inside folder
                    else:
                        root = os.path.abspath(os.path.join(root)) 
                        self.logger.debug('No dicom files were found within this folder %s', root)

                # log finishing all current path files
                self.logger.info('Finished looking at %s', path)

            # log finishing all parsed paths
            self.logger.info('Finished all search for files. A total of {0} file were sucessfully sent'.format(str(self.file_counter)))

    # exit class routine
    def __exit__(self, exc_type, exc_value, traceback):
        '''
            Function to release all application entity associations instancies
        '''

        # releasing all active connections associations
        self.logger.info("Releasing all active association...")
        for association in associations:

            # release association
            self.logger.debug("Releasing {0} association...".format(association.title))
            try:
                # release association
                association.instance.release()
                self.logger.debug("Association {0} successfully released".format(association.title))

                # remove instance of released association
                associations.remove(association)
            except Exception as e:
                self.logger.debug("Association {0} release failed".format(association.title))

        if len(associations) == 0:
            self.logger.info("All associations successfully released")
        else:
            self.logger.info("Some associations release failed: {0}".format(associations))

# class for associations with application entities
class Association(object):

    # initialize an instance
    def __init__(self, title, addr, port):
        '''
            ok
        '''

        # setup logger
        self.logger = logger.adapter
        self.verbose = logger.verbose

        # setup ae parameters
        self.addr = addr
        self.contexts = []
        self.port = int(port)
        self.title = title
        self.transfer_syntax = []

        # setup association instance parameters
        self.instance = None
        self.status = False
        
        # start global association array
        global associations
        associations = []

        # output message
        self.output = "AE: {0}, IP: {1}, PORT: {2}".format(title, addr, str(port))

        # instance of AE for parsed title
        self.ae = AE(ae_title=str(title))

        self.echo()
            
    # C-ECHO function for echoing application entity
    def echo(self):
        '''
            Function to send C-ECHO to a receiver Application Entity
            Verification SOP Class has a UID of 1.2.840.10008.1.1
            we can use the UID string directly when requesting the presentation
            contexts we want to use in the association

            Send a DIMSE C-ECHO request to the peer
            status is a pydicom Dataset object with (at a minimum) a
            (0000, 0900) Status element
        '''

        # echo context uuid
        self.context = ['1.2.840.10008.1.1']

        # object with connection.status and connection.assoc
        connection = self.open(self.ae, self.context)

        if self.instance.is_established:
            try:
                # get C-ECHO status
                status = self.instance.send_c_echo()

                # output the response from the peer
                if status:
                    self.status = True
                    self.logger.debug('C-ECHO at {0} returned STATUS: 0x{1:04x}'.format(self.output, status.Status))
            
            # 
            except Exception as e:
                self.logger.error('C-ECHO at {0} could not return any status. ERROR: {1}'.format(self.output, e))

        # 
        else:
            self.logger.debug('association with peer was not sucessfull')

    # function to establish an association with an AE
    def open(self, ae, contexts=[]):
        '''
            Function to start new association and keep it open
            until all files aimed to the referenced application
            entity could be sent

            Arguments:
                ae: instance of aimed application entity
                contexts: and array of dicom contexts
        '''

        # parse all context values to AE instance
        self.ae.requested_contexts = StoragePresentationContexts

        for context in contexts:
            self.ae.add_requested_context(context)

        # associate with the peer AE
        self.logger.debug('Requesting Association with the peer {0}'.format(self.output))
        assoc = self.ae.associate(
            self.addr, 
            self.port, 
            ae_title=self.title
            )

        # check association
        if assoc.is_established: 

            # retrieve instance of the established association
            self.instance = assoc
            
            # log association status
            self.logger.debug('Association accepted by the peer')
        
        # if any error: Release the association and log it
        elif assoc.is_rejected:
            assoc.release()
            self.logger.debug('Association was rejected by the peer')
        elif assoc.is_aborted:
            assoc.release()
            self.logger.debug('Received an A-ABORT from the peer during Association')
        else:
            assoc.release()
            self.logger.debug('No status value was received from the peer')

    # function to use C-STORE to store a dicom file to an AE
    def store(self, dcmfile):
        '''
            Function to C-STORE a dicom file into a remote receiver 

            Arguments:
                connection: Parameters for sending DICOM files
                    connection.aet: Application Entity Title, the PACS 'given name'
                    connection.addr: short for address, the IP Address of the server wich is runnig
                    connection.port: usually 11112 for dicom comunication, but customable
                dcmfile: A file path already parsed as DICOM valid file
        '''

        # store flag basic value
        store_status = False

        # check if association is successfully established
        self.logger.debug('Check if association {0} is established'.format(self.title))
        if self.instance.is_established:
            try:
                # Read the DICOM dataset from file 'dcmfile'
                self.logger.debug('Retrieve dataset from {0}'.format(dcmfile))
                dataset = read_file(dcmfile)
                self.logger.debug('Dataset retrieved')
                
                # Send a C-STORE request to the peer with 'dcmfile'
                self.logger.debug('C-STORE call, waiting for server status response... ')
                status = self.instance.send_c_store(dataset)

                # output the response from the peer
                if status:
                    self.verbose('C-STORE at {0} returned STATUS: 0x{1:04x}'.format(self.output, status.Status))

                    # verbose data for success C-STORE of DICOM file
                    self.retrieve_dataset(dataset)

                    # return true for C-STORE of 'dcmfile'
                    store_status = True

            # on exception log the error
            except Exception as e:
                self.logger.error('C-STORE at {0} could not return any status. ERROR: {1}'.format(self.output, e))
        
        # retrieve C-STORE success bool
        return store_status

    # function to retrieve data from a dicom dataset
    def retrieve_dataset(self, dataset):
        '''
            Function to retrieve DICOM dataset desired values to verbose them

            Argument:
                dataset: a dicom array of variables and values from DICOM standards
        '''

        # dicom dataset values to be used in the verbose output
        data = [
            # 'AccessionNumber',
            # 'AcquisitionDate',
            # 'AcquisitionTime', 
            # 'BitsAllocated', 
            # 'BitsStored', 
            # 'CineRate', 
            # 'Columns', 
            # 'ContentDate', 
            # 'ContentTime', 
            # 'ContrastBolusAgent', 
            # 'DeviceSerialNumber', 
            # 'DistanceSourceToDetector', 
            # 'DistanceSourceToEntrance', 
            # 'DistanceSourceToPatient', 
            # 'ExposureTime', 
            # 'FrameDelay', 
            # 'FrameIncrementPointer', 
            # 'FrameTime', 
            # 'HighBit', 
            # 'ImageType', 
            # 'ImagerPixelSpacing', 
            # 'InstanceCreationTime', 
            # 'InstanceNumber', 
            'InstitutionName', 
            'InstitutionalDepartmentName', 
            # 'KVP', 
            # 'Laterality', 
            # 'LossyImageCompression', 
            # 'Manufacturer', 
            # 'ManufacturerModelName', 
            'Modality', 
            # 'NumberOfFrames', 
            # 'PatientBirthDate', 
            # 'PatientID', 
            # 'PatientName', 
            # 'PatientOrientation', 
            # 'PatientSex', 
            # 'PerformedProcedureStepID', 
            # 'PerformedProcedureStepStartDate', 
            # 'PerformedProcedureStepStartTime', 
            # 'PerformingPhysicianName', 
            # 'PhotometricInterpretation', 
            # # 'PixelData', 
            # # 'PixelIntensityRelationship', 
            # 'PixelRepresentation', 
            # 'PositionerMotion', 
            # 'PositionerPrimaryAngle', 
            # 'PositionerSecondaryAngle', 
            # 'ProtocolName', 
            # 'RadiationSetting', 
            # 'RecommendedDisplayFrameRate', 
            # 'ReferringPhysicianName', 
            # 'Rows', 
            # 'SOPClassUID', 
            # 'SOPInstanceUID', 
            # 'SamplesPerPixel', 
            # 'SeriesDate', 
            # 'SeriesDescription', 
            # 'SeriesInstanceUID', 
            'SeriesNumber', 
            # 'SeriesTime', 
            # 'ShutterLeftVerticalEdge', 
            # 'ShutterLowerHorizontalEdge', 
            # 'ShutterRightVerticalEdge', 
            # 'ShutterShape', 
            # 'ShutterUpperHorizontalEdge', 
            # 'SoftwareVersions', 
            'StationName', 
            'StudyDate', 
            'StudyDescription', 
            'StudyID', 
            'StudyInstanceUID', 
            'StudyTime', 
            # 'TableMotion', 
            # 'WindowCenter', 
            # 'WindowWidth', 
            # 'XRayTubeCurrent', 

            # # '_convert_YBR_to_RGB', 
            # # '_dataset_slice', 
            # # '_get_pixel_array', 
            # # '_is_uncompressed_transfer_syntax', 
            # # '_pretty_str', 
            # # '_reshape_pixel_array', 
            # # '_slice_dataset', 

            # # 'add', 
            # # 'add_new', 
            # # 'clear', 
            # # 'convert_pixel_data', 
            # # 'copy', 
            # # 'data_element', 
            # # 'decode', 
            # # 'decompress', 
            # # 'formatted_lines', 
            # # 'fromkeys', 
            # # 'group_dataset', 
            # 'is_original_encoding', 
            # # 'pixel_array', 
            # # 'pop', 
            # # 'popitem', 
            # # 'remove_private_tags', 
            # # 'setdefault', 
            # # 'top', 
            # # 'trait_names',
            # # 'values', 
            # # 'walk'
        ]

        # get a temporary output variable
        temp = ''

        # increment the temporary output variable within desired data from parsed dataset
        for data_title in data:
            try:
                temp = temp + '\n {0}: {1}'.format(data_title, getattr(dataset, data_title))
            except Exception as e:
                self.logger.debug('Could not retrieve {0} out of {} dicom file'.format(data_title, getattr(dataset, 'StudyID')))

        # concatenate temporary output variable with formated output message
        output = 'Retrieve dicom dataset while omitting patient sensitive data \n' +\
        '\n >> ============================ <<' + temp + '\n'

        # verbose output for success on C-STORE DICOM files
        self.verbose(output)

# class for paths argument parser
class PathsValidity(object):

    # path validity init
    def __init__(self):
        ''' 
            Initiate a DICOM Populate Path Validity instance.

            Argument:
                logger: a logging instance for output and log
        '''

        # setup logger
        self.logger = logger.adapter
        
    # path validity checker function
    def validate(self, paths):
        '''
            Function to check if each parsed path is a valid system file or folder
            and if it can be accessed by the code.

            Arguments:
                paths: array of files and folders to be checked
        '''

        # set basic variable for valid files
        valid_paths = []

        # loop check through parsed path
        self.logger.debug('Checking validity of parsed paths')
        for path in paths:

            # check if path exist
            if not os.access(path, os.F_OK):
                output = "Path {0} could not be found, therefore will be ignored".format(path)
                self.logger.debug(output)

            # check if path has read permitions on
            if not  os.access(path, os.R_OK):
                output = "Path {0} does not have read permitions on, therefore will be ignored".format(path)
                self.logger.debug(output)

            # append path to a valid paths array if it exists and is accessible    
            else:
                valid_paths.append(path)

        # return all parsed valid paths
        return valid_paths

# class for connection argument parser
class ConnectionsValidity(object):

    # path validity init
    def __init__(self):
        ''' 
            Initiate a DICOM Populate connection Validity instance.

            Argument:
                logger: a logging instance for output and log
        '''

        # setup logger
        self.logger = logger.adapter
        self.verbose = logger.verbose

    # connection validity checker function
    def validate(self, connections):
        '''
            Function to check if each parsed connection is a valid application entity connection
            and if it can be remote accessed by the code.

            Arguments:
                connections: array of parameters for a application entity connection to be checked
        '''

        # check validity for each connection
        self.logger.debug('Checking validity of parsed connections')
        for connection in connections:

            # check if connection minimum format passed is not correct
            if not connection.count('@') == 1 or not connection.count(':') == 1:
                self.logger.error('Wrong connection format was passed: %s',connection)

            # if the minimun format is correct
            else:

                # get AE Title from connection
                title = str(connection.split('@')[0])

                # get TCP/IP Address from connection
                addr = connection.split('@')[1].split(':')[0]

                # try to parse tcp/ip port as an integer 
                try:
                    port = int(connection.split('@')[1].split(':')[1])
                except Exception as e:
                    self.logger.error('Wrong connection TCP/IP Port was passed: %s', port)
                    continue

                # output message
                output = "AE: {0}, IP: {1}, PORT: {2}".format(title, addr, str(port))

                # check if ae_title is in correct format
                if not re.match(r"^\w+$",title):
                    self.logger.error('Wrong connection AE Title was passed: %s', title)

                # check if tcp/ip address is in correct format
                elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",addr):
                    self.logger.error('Wrong connection TCP/IP Address was passed: %s', addr)

                # check if tcp/ip port is in correct format
                elif not re.match(r"^\d{2,5}$",str(port)) and int(port):
                    self.logger.error('Wrong connection TCP/IP Port was passed: %s', port)

                # else all regex parsed and connection has the minimum format
                else:
                    # setup associations instancies
                    for connection in connections:
                        '''
                            Associantion object:
                                assoc.status [bool value]
                                assoc.instance [Association]
                                assoc.addr [tcp/ip address]
                                assoc.contexts [dicom context array]
                                assoc.port [tcp/ip port]
                                assoc.title [Application Entity Title]

                        '''
                        assoc = Association(title, addr, port)

                        # if association status exist
                        if assoc.status:

                            # append association into global array
                            associations.append(assoc)
                        
                        # is there is not an association, log error
                        else:
                            # output message
                            message = "{0} cound not be reached".format(output)

                            # log message
                            self.logger.error(message)

        # return valid parameters for application entities
        return associations

# class for logger instancies and configurations
class Logger(object):

    # path validity init
    def __init__(self, folder, format, debug_flag, extra, verbose_flag):
        ''' 
            Initiate a DICOM Populate Logger instance.

            Argument:
                logger: a logging instance for output and log
        '''

        # 
        log = {
            # setup of log folder
            'folder': folder,
            # set logging basic config variables
            'level': 'INFO',
            # 
            'date_format': '%Y-%m-%d %H:%M:%S',
            # 
            'filepath': folder+'/'+__project__+'.log',
            #
            'format': format,
            # extra data into log formatter
            'extra': extra
        }

        # set log name
        logger = logging.getLogger(__project__+'-'+__version__)

        # set formatter
        formatter = logging.Formatter(log['format'])

        # check debug flag
        if debug_flag:
            logger.setLevel('DEBUG')
        else:
            logger.setLevel('INFO')

        # check if log folder exists
        if not os.path.exists(log['folder']):
            print("Log folder:",log['folder'],"not found")
            try:
                os.makedirs(log['folder'])
                print("Log folder:",log['folder'],"created")
            except Exception  as e:
                print("Log folder:",log['folder'],"could not be created, error:", e)
                sys.exit()

        # setup of file handler
        file_handler = logging.FileHandler(log['filepath'])     
        file_handler.setFormatter(formatter)

        # setup of stream handler
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)

        # add handler to the logger
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

        # update logger to receive formatter within extra data
        logger = logging.LoggerAdapter(logger, log['extra'])

        self.adapter = logger
        self.verbose_flag = verbose_flag

    # function for print info logs on output in case of verbose flag
    def verbose(self, message):
        '''
            Verbose is a DICOM Populate function to check if and flag for verbose
            was passed and output iformation on each sent files

            Arguments:
                message: receive output or log message and pass it through only if
                    the verbose flag is setted
        '''

        # check verbose flag and log it
        if self.verbose_flag:
            self.adapter.info(message)
            
# command line argument parser
def args(args):
    '''
        Main function for terminal call of library

        Arguments:
            args: receive all passed arguments and filter them using
                the argparser library
    '''

    # argparser init
    parser = argparse.ArgumentParser(
        description=short_description
    )

    # path argument parser
    parser.add_argument(
        '-p','--paths',
        nargs='+',
        help='dicom folders or files paths', 
        default="check_string_for_empty",
        required=True
    )

    # connection argument parser
    parser.add_argument(
        '-c','--connections',
        nargs='+',
        help='the connection parameters for dicom receivers',
        default="check_string_for_empty",
        required=True
    )

    # debug flag argument parser
    parser.add_argument(
        '-d','--debug',
        action='store_true', 
        help='process debug flag \
            (it only shows debug information and \
            can be combined with the verbose flag for \
            a more robust output and log)',
        default=False,
        required=False
    )

    # version output argument parser
    parser.add_argument(
        '-v','--version',
        action='version', 
        help='output software version',
        default=False,
        version=(__project__+"-"+__version__)
    )

    # verbose flag argument parser
    parser.add_argument(
        '--verbose',
        action='store_true', 
        help='make output info more verbose \
            (it only shows output information and \
            can be combined with debug flag for \
            a more robust output and log)',
        default=False,
        required=False
    )

    # passing filtered arguments as array
    args = parser.parse_args()

    '''
        Function to run the populate main script

        Arguments:
            debug=False
            paths=[]
            connections=[]
            verbose=False
    '''
    run(args.debug, args.paths, args.connections, args.verbose)

# run script function
def run(debug=False, paths=[], connections=[], verbose=False):
    '''
        Function to be call using library as a module on a script.py type of file
        or via terminal through the args() function

        Arguments:
            debug_flag: set the debug output; default=False
            paths: An array of paths os DICOM files; default = []
            connections: parameters for sendind files to PACS environments; default = []
            verbose_flag: sent the output for every file parsed; default=False
    '''

    # start execution timer
    start_time = time.time()

    # normalizing variables
    debug_flag = debug
    verbose_flag = verbose

    # standard log folder
    log_folder = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../log/'))

    # standard log format
    log_format = '%(asctime)-8s %(levelname)-5s [%(project)s-%(version)s] user: %(user)s LOG: %(message)s'

    # creates a logger instance from class Logger within:
    # an adapter (the logging library Logger Adapter) and the verbose flag
    global logger
    logger = Logger(
        folder = log_folder,
        format = log_format,
        debug_flag = debug_flag,
        extra = {
            'project':  __project__,
            'version':  __version__,
            'user':     getpass.getuser()
        },
        verbose_flag = verbose_flag
    )

    # output log folder location
    logger.adapter.debug('Log file located at {0}'.format(log_folder))

    # check validity of the paths parsed
    path_validator = PathsValidity()
    paths = path_validator.validate(paths)

    # check if validate paths remained
    if not len(paths) > 0:
        logger.adapter.error('No paths were successfully parsed. Exiting...')
        sys.exit()
    else:
        logger.adapter.info('Following path(s) were successfully parsed: {0}'.format(paths))

    # check validity of the paths parsed
    connections_validator = ConnectionsValidity()
    connections = connections_validator.validate(connections)

    # check if validate connections remained
    if not len(connections) > 0:
        logger.adapter.error('No connections were successfully parsed. Exiting...')
        sys.exit()
    else:
        # get a valid connections array with only application entities titles
        valid_connections = []
        for connection in connections:
            valid_connections.append(connection.title)
        # log information
        logger.adapter.info('Following connection(s) were successfully parsed: {0}'.format(valid_connections))

    # populate pacs servers with given folders dicom files
    with Populate(paths) as populate:
        populate.send()

    # log the execution time
    exec_time = str(datetime.timedelta(seconds=(time.time() - start_time)))

    if int(exec_time.split(':')[0]) != 0:
        exec_hours = exec_time.split(':')[0] + ' hours '
    else:
        exec_hours = ''

    if int(exec_time.split(':')[1]) != 0:
        exec_minutes = exec_time.split(':')[1] + ' minutes '
    else:
        exec_minutes = ''

    if float(exec_time.split(':')[2]) != 0:
        exec_seconds = exec_time.split(':')[2] + ' seconds'
    else:
        exec_seconds = ''

    exec_time_formatted = exec_hours+exec_minutes+exec_seconds

    logger.adapter.info('Entire process took {0}'.format(exec_time_formatted)
    )

# main function
if __name__ == "__main__":
    args(sys.argv[1:])
# end of code