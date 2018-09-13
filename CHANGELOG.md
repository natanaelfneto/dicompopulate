# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Released]

### 0.4 - 2018-09-12
#### Changed
- changed logger routines to separated class Logger
- added pydicom module for checking if file is dicom valid
- added proto function to echo validade aet@ip:port conections

#### Added
- added verbose flag
- added separated verbose and debug outputs but still available for combination of flags

### 0.3 - 2018-09-09
#### Changed
- renamed run.py to main.py
- added possibility for multi paths to be sent with a PathValidity Class
- added possibility for multi pacs creceivers with a ConectionValidity Class
- removed python-tail due to hard usage and buggy package name
- added log folder generation insted of loosed files

### 0.2 - 2018-09-08
#### Changed
- replace of the console output and log file writing with the python logging and a python-tail modules
- renamed dicom_populate.py to run.py
- added modules folder for non pip third party modules
- added assets folder for better organization

### 0.1 - 2018-09-07
#### Added
- added dcm4chee-2.0.29 binaries
- added dicom_populate.py script with basic run of DCMSND for dicom files inside folder and subfolders
- very basic usage og a log file and console output
- added argsparser module

## [Unreleased]

### 0.0 - 2018-09-07
#### Added
- project created