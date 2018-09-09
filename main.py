#!/usr/bin/env python
from __future__ import print_function
# third party imports
import argparse
import logging
import os
import re
import sys
# local imports

# module version
__version__ = "0.3"

# main class
class Populate(object):
    # represents a tail command
    def __init__(self):
        ''' 
            Initiate a DICOM Populate instance.
            
            Arguments for send():
                files: Array of files and/or folder to be sent to a PACS environment
                aet: Application Entity Title, the PACS 'given name'
                addr: short for address, the IP Address of the server wich is runnig
                port: usually 11112 for dicom comunication, but customable
        '''
    # 
    def send(self, paths, conections):
        # set basic variables
        files = []  # array of files
        i = 0       # file counter
        # loop through folder
        logger.debug('Looping throug folder and subfolders...')
        for path in paths:
            for root, dirs, files in os.walk(path):
                # check if folder is not empty
                if files:
                    for file in files:
                        # get absolute path
                        file_path = os.path.abspath(os.path.join(root, file))
                        # increment file counter
                        i = i + 1
                        for conection in conections:
                            logger.info(
                                'Sending file %s: %s to %s@%s:%s',
                                str(i),
                                file_path,
                                conection['ae_title'],
                                conection['addr'],
                                conection['port']
                                )
                else:
                    # if no file is found inside folder, log it down
                    root = os.path.abspath(os.path.join(root))
                    logger.debug('No file found inside this folder %s', root)
            logger.info('Finished sending all files from %s', path)
        logger.info('Finished sending all files')

# paths argument parser
class PathsValidity(object):
    # path validity init
    def __init__(self):
        ''' 
            Initiate a DICOM Populate Path Validity instance.
        '''
    # path validity checker function
    def checker(self, paths):
        logger.debug('checking validity of parsed files and folders')
        for path in paths:
            if not os.access(path, os.F_OK) and not os.access(path, os.R_OK):
                logger.debug( \
                    "Path '%s' could not be found or does not have read permitions, \
                    therefore will be ignored", path
                    )
                paths.remove(path)
        logger.debug("Paths '%s' was/were found", paths)

        return paths

# conection argument parser
class ConectionValidity(object):
    # path validity init
    def __init__(self):
        ''' 
            Initiate a DICOM Populate Conection Validity instance.
        '''
    # conection validity checker function
    def checker(self, conections):
        logger.debug('checking validity of parsed conections')
        # set basic variables
        aes = []    # array for AEs
        for conection in conections:
            # check if conection format passed is correct
            if not conection.count('@') == 1 or not conection.count(':') == 1:
                logger.debug('Wrong conection format was passed: %s', conection)
            else:
                # get AE Title format
                ae_title = conection.split('@')[0]
                # get TCP/IP Address format
                addr = conection.split('@')[1].split(':')[0]
                # get TCP/IP Port format
                port = conection.split('@')[1].split(':')[1]
                # check if ae_title, address and port are in correct format
                if not re.match(r"^\w+$",ae_title):
                    logger.debug('Wrong conection AE Title was passed: %s', ae_title)
                elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",addr):
                    logger.debug('Wrong conection TCP/IP Address was passed: %s', addr)
                elif not re.match(r"^\d{4,5}$",port):
                    logger.debug('Wrong conection TCP/IP Port was passed: %s', port)
                else:
                    aes.append({
                        'ae_title': ae_title,
                        'addr': addr,
                        'port': port
                    })

        return aes

if __name__ == "__main__":
    # argparser init
    parser = argparse.ArgumentParser(
        description='a sender for folders of dicom files in python'
    )
    # path argument parser
    parser.add_argument(
        '-p','--paths',
        nargs='+',
        help='dicom folders or files path', 
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
        help='process debug flag',
        default=False,
        required=False
    )
    # verbose flag argument parser
    parser.add_argument(
        '-v','--verbose',
        action='store_true', 
        help='runtime verbose flag',
        default=False,
        required=False
    )
    # passing filtered arguments as array
    args = parser.parse_args() 

    # setting logging basic config avriables
    log_folder = 'log'
    if args.debug:
        log_level = 'DEBUG'
        log_file = log_folder+'/populate_debug.log'
        log_format = '%(asctime)s %(name)s %(levelname)s %(message)s'
        log_date_format = '%Y-%m-%d %H:%M:%S'
    else:
        log_level = 'INFO'
        log_file = log_folder+'/populate_info.log'
        log_format = '%(asctime)s %(levelname)s %(message)s'
        log_date_format = '%Y-%m-%d %H:%M:%S'
    
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    # setting logging basic config
    logging.basicConfig(
        level=getattr(logging,log_level),
        format=log_format,
        datefmt=log_date_format,
        filename=log_file,
        filemode='a+'
        )
    logger = logging.getLogger(__name__)

    # temporary tail with terminal execution
    if args.verbose:
        os.system('tail -f populate_info.log &')
    if args.verbose and args.debug:
        os.system('tail -f -n 1 populate_*.log &')

    # check validity of the paths parsed
    paths = PathsValidity()
    paths = paths.checker(args.paths)

    # check validity of the paths parsed
    conections = ConectionValidity()
    conections = conections.checker(args.conections)

    populate = Populate()
    populate.send(paths, conections)