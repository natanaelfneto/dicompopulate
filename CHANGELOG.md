# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Released]

## [Unreleased]
### 0.5 - 2018-09-15
### Added
- process execution timer

### 0.4 - 2018-09-12
#### Changed
- logger routines to separated class Logger
- change logger from class input to global variable

#### Added
- verbose flag
- separated verbose and debug outputs but still available for combination of flags
- pydicom module for checking if file is dicom valid
- function to echo validade aet@ip:port conections
- function to store dicom to valid aet@ip:port

### 0.3 - 2018-09-09
#### Changed
- renamed run.py to main.py
- removed python-tail due to hard usage and buggy package name

### Added
- possibility for multi paths to be sent with a PathValidity Class
- possibility for multi pacs creceivers with a ConectionValidity Class
- log folder generation insted of loosed files

### 0.2 - 2018-09-08
#### Changed
- replace of the console output and log file writing with the python logging and a python-tail modules
- renamed dicom_populate.py to run.py

#### Added
- modules folder for non pip third party modules
- assets folder for better organization

### 0.1 - 2018-09-07
#### Added
- dcm4chee-2.0.29 binaries
- dicom_populate.py script with basic run of DCMSND for dicom files inside folder and subfolders
- a very basic usage og a log file and console output
- argsparser module

### 0.0 - 2018-09-07
#### Added
- project created