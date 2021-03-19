debugging command, ie webhook on demand with the proper checksum function included

submit_hook.py expects three arguments: 
arg 1: path to json file of the payload you want to se
arg 2: url of webhook destination you want it sent to
arg 3: the shared secret to sign the payload with for verification at destination

`python submit_hook.py data/snap_vulns.json https://webhookurl/ 'averylongsecrettouseforthis'`

For testing/validating that this works, [https://webhook.site/](https://webhook.site/) will generate a public webhook url you can use and see the payload in action. This is good to also see what Snyk is sending (and capturing a payload from your snyk org for replay by this script)

Snyk Webhooks can only be enabled by the API in the beta, refer to our API docs on [how to do that](https://snyk.docs.apiary.io/#reference/webhooks/webhook-collection/create-a-webhook).