<p align="left">
  <a href="#">
    <img alt="dicom-populate-python-script-logo" src="https://raw.githubusercontent.com/natanaelfneto/.png" width="240"/>
  </a>
</p>

**DICOM Populate** was based on the DCM4CHEE binaries do send folders of dicom files to a PACS
Version: **0.0.1**
***
# Table of Contents
* [Getting Started](#getting-started)
    * [Installation process](#installation-process)
    * [Usage](#usage)
* [License](#license)
***
## Getting Started
### Via Bash
#### Installation Process
_installation is still under development, to make it work_
_clone or download the repository at_
```Shell
git clone https://github.com/natanaelfneto/.git;
```
_run the command as examplified:
```Shell
python dicom_populate.py --path /PACS/ --pacs DCM4CHEE --address 10.0.0.1 --port 11112
```
_enjoy_
***
## Usage
_this messagem can also be found with_ **python ./.py -h** _command_
```ShellSession
usage: dicom_populate.py [-h] -p PATH -c PACS -a ADDRESS -P PORT [-v] [-l]

A DCM4CHEE usage with python script

optional arguments:
  -h, --help                        show this help message and exit
  -p PATH, --path PATH              dicom folder path
  -c PACS, --pacs PACS              ae title of destination PACS
  -a ADDRESS, --address ADDRESS     ip address of destination PACS
  -P PORT, --port PORT              port of destination PACS
  -v, --verbose                     process verbose flag
  -l, --log                         save log file
```
## License
MIT License

Copyright (c) 2017 Natanael F. Neto (natanaelfneto)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.