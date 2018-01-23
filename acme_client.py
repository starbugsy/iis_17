#!/usr/bin/env python

import argparse # for parsing the arguments
import subprocess # similar to fork in c
import json # for using json
import os
import sys
import base64 # for encoding in utf urlsafe base64
import binascii
import time
import hashlib
import re # for regexes
import copy
import textwrap
import logging

# our client was build on the parent acme_tiny.py
# author: Sandro Letter



if __name__ == '__main__':
    main(sys.argv[1:])