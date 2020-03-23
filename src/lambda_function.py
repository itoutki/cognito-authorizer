import json
import jose
import requests
import time
from jose import jwt, jwk
from jose.utils import base64url_decode

def lambda_handler(event, context):
    print(event)
    token = -1
    if 'headers' in event :
        if 'authorization' in event['headers'] :
            token = event['headers']['authorization']

    print(token)
    if token == '1':
        print('Allow')
        return {
            'principalId': 1,
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': '*',
                        'Effect': 'Allow',
                        'Resource': 'arn:aws:execute-api:*:*:*/*/*/'
                    }
                ]
            }
        }
    
    print('Deny')
    return {
        'principalId': 1,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': '*',
                    'Effect': 'Deny',
                    'Resource': 'arn:aws:execute-api:*:*:*/*/*/'
                }
            ]
        }
    }

