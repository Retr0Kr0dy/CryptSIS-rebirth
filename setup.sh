#!/bin/bash

echo 
echo "  Installing dependencies ..."
echo
echo "  | Installing blowfish lib"
echo
python3 -m pip install blowfish
echo
echo "  | Installing pycryptodome lib"
echo
python3 -m pip install pycryptodome
echo
echo "  | Installing cryptography lib"
echo
python3 -m pip install cryptography
echo 
echo "  Succed !!! All depencies are installed"
