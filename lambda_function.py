import json
import jose
import requests
import time
from jose import jwt, jwk
from jose.utils import base64url_decode

def lambda_handler(event, context):
    token = event['headers']['Authorization']
    return token

