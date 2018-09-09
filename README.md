<p align="left">
  <a href="#">
    <img 
      alt="dicom-populate-python-script-logo" 
      src="https://raw.githubusercontent.com/natanaelfneto/dicom_populate/master/assets/dp-logo.png" 
      width="240" />
  </a>
</p>

**DICOM Populate** is small code to send folders of dicom files to many desired PACS server receivers
Version: **0.3**
***
# Table of Contents
* [Getting Started](#getting-started)
    * [Installation process](#installation-process)
    * [Usage](#usage)
    * [TODO](#TODO)
* [License](#license)
***
## Getting Started
### Via Bash
#### Installation Process
_installation is still under development, to make it work_
_clone or download the repository at:_
```Shell
git clone https://github.com/natanaelfneto/dicom_populate.git
```
_run the command as examplified:_
```Shell
python main.py --paths /PACS/1/ /PACS/2/ /PACS/3/ --conections DCM4CHEE@10.0.0.1:11112 OTHER@127.0.0.1:5555
```
_enjoy_
***
## TODO
* add _'localhost'_, _'pacs.example.com'_, names support insted or just pure IP Addresses
## Usage
_this messagem can also be found with_ **python dicom_populate.py -h** _command_
```ShellSession
usage: main.py [-h] -p PATHS [PATHS ...] -c CONECTIONS [CONECTIONS ...] [-d] [-v]

a sender for folders of dicom files in python

optional arguments:
  -h, --help                                                                  show this help message and exit
  -p PATHS [PATHS ...], --paths PATHS [PATHS ...]                             dicom folders or files paths
  -c CONECTIONS [CONECTIONS ...], --conections CONECTIONS [CONECTIONS ...]    the conection parameters for dicom receivers
  -d, --debug                                                                 process debug flag
  -v, --verbose                                                               runtime verbose flag
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