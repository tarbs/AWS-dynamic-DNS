#AWS-dynamic-DNS

Dynamic DNS via AWS for those without static IPs.

Created with Serverless v1.4

##Prerequisites

* An AWS account that you have admin access to.
* A hosted zone within Route53 of the AWS account.
* The AWS CLI installed and configured on your workstation with access to the AWS account.
* Serverless 1.4+ installed on your workstation.

##Installation and deployment

1. Clone this repository
2. Copy __"example-configuration.yml"__ to __"configuration.yml"__ and set __AWS-region__, __AWS-hosted-zone-name__, and __AWS-DNS-address__ to appropriate values within __"configuration.yml"__.
3. Execute __"serverless deploy"__ to deploy the function to your AWS account.
4. Record the value of __DNSKey__ from the deployment output - this is your API key for access to the DNS update API.
5. Record the __endpoint__ address of the deployed API - this is the address you will be calling.
5. Call the API from the IP address that you want Dynamic DNS for (remembering to supply the API Key).

An example Linux curl command:

    curl -H "x-api-key: __<your key here>__" -H "Content-Type: application/json" __<your API endpoint here>__ 
