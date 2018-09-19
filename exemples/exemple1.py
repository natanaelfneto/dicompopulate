#!/usr/bin/env python
from __future__ import *

from populate import populate

# get all files and paths to send
path_1 = '/PACS/1/'
path_2 = '/PACS/2/'
path_3 = '/PACS/3/dicom.dcm'

# get all desired conections to receive
c_1 = 'DCM4CHEE@10.0.0.1:11112'
c_2 = 'OTHER@127.0.0.1:5555'

# populate
populate.run(
  debug=True,
  verbose=True,
  max_workers=10,
  paths=[ path_1, path_2, path_3 ],
  conections=[ c_1, c_2 ]
)