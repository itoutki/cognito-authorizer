import json
import jose
import requests
import time
import os
from http import HTTPStatus
from jose import jwt, jwk
from jose.utils import base64url_decode

region = os.getenv('REGION')
user_pool_id = os.getenv('USER_POOL_ID')
client_ids = os.getenv('CLIENT_ID')
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, user_pool_id)

def lambda_handler(event, context):
    print(json.dumps(event))

    token = -1
    lower_headers = {}
    if 'headers' in event :
        for k in event['headers'].keys() :
            lower_headers[k.lower()] = event['headers'][k]

    if 'authorization' in lower_headers :
        token = lower_headers['authorization']

    jwt_headers = jwt.get_unverified_headers(token)
    kid = jwt_headers['kid']
    res_cognito = requests.get(keys_url)

    if res_cognito.status_code != HTTPStatus.OK:
        return {
            'principalId': 1,
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': '*',
                        'Effect': 'Deny',
                        'Resource': event['methodArn']
                    }
                ]
            }
        }

    keys = json.loads(res_cognito.text)['keys']
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        return {
            'principalId': 1,
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': '*',
                        'Effect': 'Deny',
                        'Resource': event['methodArn']
                    }
                ]
            }
        }

    public_key = jwk.construct(keys[key_index])

    message = str(token).rsplit('.', 1)[0].encode('utf-8')
    encoded_signature = str(token).rsplit('.', 1)[1].encode('utf-8')

    decoded_signature = base64url_decode(encoded_signature)

    if not public_key.verify(message, decoded_signature):
        return {
            'principalId': 1,
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': '*',
                        'Effect': 'Deny',
                        'Resource': event['methodArn']
                    }
                ]
            }
        }

    claims = jwt.get_unverified_claims(token)
    print(json.dumps(claims))

    if time.time() > claims['exp']:
        return {
            'principalId': 1,
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': '*',
                        'Effect': 'Deny',
                        'Resource': event['methodArn']
                    }
                ]
            }
        }
    if claims['aud'] not in client_ids:
        return {
            'principalId': 1,
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': '*',
                        'Effect': 'Deny',
                        'Resource': event['methodArn']
                    }
                ]
            }
        }
    
    return {
        'principalId': claims['email'],
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': '*',
                    'Effect': 'Allow',
                    'Resource': event['methodArn']
                }
            ]
        }
    }

