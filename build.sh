#!/bin/bash

rm -rf dist
mkdir dist
cp -r src/* dist
pipenv lock -r > requirements.txt
pip install -r requirements.txt -t dist
rm requirements.txt

