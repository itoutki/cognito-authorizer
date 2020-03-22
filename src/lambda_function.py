import json
import jose
import requests
import time
from jose import jwt, jwk
from jose.utils import base64url_decode
Authorization
def lambda_handler(event, context):
    token = event['headers']['Authorization']
    
    if token == '1':
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
