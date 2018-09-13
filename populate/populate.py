#!/usr/bin/env python

# project name
__project__ = "populate"

# project version
__version__ = "0.4"

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
import getpass
import logging
import pydicom
import os
import re
import sys

from pynetdicom3 import AE

# class for populate application entities
class Populate(object):

    # initialize an instance
    def __init__(self, logger):
        ''' 
            Initiate a DICOM Populate instance.

            Argument:
                logger: a logging instance for output and log
        '''

        # setup logger
        self.logger = logger.adapter
        self.verbose = logger.verbose

    # 
    def send(self, paths, conections):
        '''
            DICOM Populate send function. Get all files inside received paths and
            send then to PACS environments with especific conections also received
            from function call

            Arguments:
                files: Array of files and/or folder to be sent to a PACS environment
                conection: Parameters for sending DICOM files
                    conection.aet: Application Entity Title, the PACS 'given name'
                    conection.addr: short for address, the IP Address of the server wich is runnig
                    conection.port: usually 11112 for dicom comunication, but customable
        '''

        # set basic variable
        i = 0

        # loop through folder
        self.logger.debug('Looping throug parsed folder and subfolders...')
        for path in paths:
            # get files inside current path
            self.logger.debug('Looping throug files inside folder and its subfolders...')
            self.logger.info('Sending files at {0}'.format(path))

            for root, dirs, files in os.walk(path):
                # check if folder is not empty
                if files:
                    # for each file founded
                    for file in files:

                        # get absolute path
                        file_path = os.path.abspath(os.path.join(root, file))

                        # check if file can be parsed as dicom
                        try:
                            dcmfile = pydicom.dcmread(file_path, force=True)
                        except Exception as e:
                            self.logger.debug("Could not parse {0} as a DICOM file".format(file_path))
                            continue

                        # send file to each available conection
                        for conection in conections:
                            try:
                                # increment file counter
                                i = i + 1

                                # output message
                                output = "File No. {0}, AE: {1}, IP: {2}, PORT: {3}, PATH: {4}".format(
                                    str(i),
                                    conection['title'],
                                    conection['addr'],
                                    conection['port'],
                                    file_path
                                )

                                # Sending file through pynetdicom3 library
                                # ...

                                # log successfully file transmition
                                self.verbose(output)
                            
                            # exception catcher
                            except Exception as e:
                                self.logger.error("Error while sendin:g {0} ERROR: {1}".format(output, e))

                # if no files were found inside folder
                else:
                    root = os.path.abspath(os.path.join(root)) 
                    self.logger.debug('No dicom files were found within this folder %s', root)

            # log finishing all current path files
            self.logger.info('Finished loop at %s', path)

        # log finishing all parsed paths
        self.logger.info('Finished all loops for files. A total of {0} were sucessfully sent'.format(str(i)))

# class for paths argument parser
class PathsValidity(object):

    # path validity init
    def __init__(self, logger):
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
        self.logger.debug('checking validity of parsed paths')
        for path in paths:

            # append path if it exists, is accessible
            if os.access(path, os.F_OK) and os.access(path, os.R_OK):               
                valid_paths.append(path)

            # if not, log the error
            else:
                output = "Path {0} could not be found or does not have read permitions on, therefore will be ignored".format(path)
                self.logger.debug(output)
        
        # return all parsed valid paths
        return valid_paths

# class for conection argument parser
class ConectionsValidity(object):

    # path validity init
    def __init__(self, logger):
        ''' 
            Initiate a DICOM Populate Conection Validity instance.

            Argument:
                logger: a logging instance for output and log
        '''

        # setup logger
        self.logger = logger.adapter

    def echo(self, title, addr, port):
        '''

        '''

        # ae status flag
        echo_status = False

        # output message
        output = "AE: {0}, IP: {1}, PORT: {2}".format(title, addr, str(port))
        self.logger.info('Trying C-ECHO at {0}'.format(output))

        # instance of AE for parsed title
        ae = AE(ae_title=str(title))

        '''
            Verification SOP Class has a UID of 1.2.840.10008.1.1
            we can use the UID string directly when requesting the presentation
            contexts we want to use in the association
        '''
        ae.add_requested_context('1.2.840.10008.1.1')

        # associate with the peer AE
        self.logger.debug('Requesting Association with the peer for {0}'.format(output))
        assoc = ae.associate(addr, port, ae_title=str(title))

        # check association
        if assoc.is_established:
            '''
                Send a DIMSE C-ECHO request to the peer
                status is a pydicom Dataset object with (at a minimum) a
                (0000, 0900) Status element
            '''
            self.logger.debug('Association accepted by the peer')

            # get association status
            status = assoc.send_c_echo()

            # output the response from the peer
            if status:
                echo_status = True
                self.logger.info('C-ECHO at {0} returned STATUS: 0x{1:04x}'.format(output, status.Status))

            # Release the association
            assoc.release()
        elif assoc.is_rejected:
            self.logger.debug('Association was rejected by the peer')
        elif assoc.is_aborted:
            self.logger.debug('Received an A-ABORT from the peer during Association')

        # return flag for successfuly echo
        return echo_status

    # conection validity checker function
    def validate(self, conections):
        '''

        '''

        # 
        valid_aes = []

        # 
        self.logger.debug('checking validity of parsed conections')
        for conection in conections:

            # check if conection format passed is correct
            if not conection.count('@') == 1 or not conection.count(':') == 1:
                self.logger.debug('Wrong conection format was passed: %s',conection)

            # 
            else:

                # get AE Title format
                title = conection.split('@')[0]

                # get TCP/IP Address format
                addr = conection.split('@')[1].split(':')[0]
                
                # get TCP/IP Port format
                port = conection.split('@')[1].split(':')[1]

                # output message
                output = "AE: {0}, IP: {1}, PORT: {2}".format(title, addr, str(port))

                # check if ae_title, address and port are in correct format
                if not re.match(r"^\w+$",title):
                    self.logger.debug('Wrong conection AE Title was passed: %s', title)

                # 
                elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",addr):
                    self.logger.debug('Wrong conection TCP/IP Address was passed: %s', addr)

                # 
                elif not re.match(r"^\d{2,5}$",port) and int(port):
                    self.logger.debug('Wrong conection TCP/IP Port was passed: %s', port)

                # 
                elif self.echo(title, addr, int(port)):
                    valid_aes.append({
                        'title': title,
                        'addr': addr,
                        'port': int(port)
                    })

                #
                else:
                    # output message
                    message = "{0} cound not be reached".format(output)

                    # log message
                    self.logger.debug(message)

        # return valid parameters for application entities
        return valid_aes

# 
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

    # conection argument parser
    parser.add_argument(
        '-c','--conections',
        nargs='+',
        help='the conection parameters for dicom receivers',
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

    # run populate routines
    run(args.debug, args.paths, args.conections, args.verbose)

# run script function
def run(debug=False, paths=[], conections=[], verbose=False):
    '''
        Function to be call using library as a module on a script.py type of file
        or via terminal through the args() function

        Arguments:
            debug_flag: set the debug output
            paths: An array of paths os DICOM files
            conections: parameters for sendind files to PACS environments
            verbose_flag: sent the output for every file parsed
    '''

    # normalizing variables
    debug_flag = debug
    verbose_flag = verbose

    # standard log folder
    log_folder = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../log/'))

    # standard log format
    log_format = '%(asctime)-8s %(levelname)-5s [%(project)s-%(version)s] user: %(user)s LOG: %(message)s'

    # creates a logger instance from class Logger within:
    # an adapter (the logging library Logger Adapter) and the verbose flag
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
    path_validator = PathsValidity(logger)
    paths = path_validator.validate(paths)

    # check if validate paths remained
    if not len(paths) > 0:
        logger.adapter.error('No paths were successfully parsed. Exiting...')
        sys.exit()
    else:
        logger.adapter.info('Some path(s) were successfully parsed')
        logger.adapter.debug('Path(s):{0}'.format(paths))

    # check validity of the paths parsed
    conections_validator = ConectionsValidity(logger)
    conections = conections_validator.validate(conections)

    # check if validate conections remained
    if not len(conections) > 0:
        logger.adapter.error('No conections were successfully parsed. Exiting...')
        sys.exit()
    else:
        logger.adapter.info('Some conection(s) were successfully parsed')
        logger.adapter.debug('Conection(s):{0}'.format(conections))

    # populate pacs servers with given folders dicom files
    populate = Populate(logger)
    populate.send(paths, conections)

# main function
if __name__ == "__main__":
    args(sys.argv[1:])
# end of code