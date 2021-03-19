import json
import requests
import hashlib
import hmac
import sys
import datetime


# debugging command, ie webhook on demand with the proper checksum function included
# python submit_hook.py data/no_new_vulns.json https://webhookurl/

JSON = sys.argv[1]
URL = sys.argv[2]
SECRET = sys.argv[3]

USERAGENT = 'Snyk-Webhooks'

def generate_signature(data: str, secret: str) -> str:

     secret_byte = secret.encode()
     data_b = data.encode()

     hmac_gen = hmac.new(key=secret_byte, msg=data_b, digestmod=hashlib.sha256)

     return hmac_gen.hexdigest()

vulns = open(JSON)

# pedantic reload of data
data = json.load(vulns)
data = json.dumps(data)

sig = generate_signature(data,SECRET)

headers = {
    'X-Hub-Signature'   : f'sha256={sig}',
    'X-Snyk-Timestamp'  : f'{datetime.datetime.now(datetime.timezone.utc).isoformat()}',
    'X-Snyk-Event'      : 'project_snapshot/v0',
    'content-type'      : 'application/json',
    'accept'            : 'application/json',
    'user-agent'        : USERAGENT
    }


print(headers)

r2 = requests.post(URL, headers=headers, data=data)

print(r2.text)
