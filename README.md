#AWS-dynamic-DNS

Dynamic DNS via AWS for those without static IPs.

Currently only supports a single target DNS alias.

Can be used to update EC2 security groups to enable ingress from the IP address calling the function.

Created with Serverless v1.4

##Prerequisites

* An AWS account that you have admin access to.
* A hosted zone within Route53 of the AWS account.
* The AWS CLI installed and configured on your workstation with access to the AWS account.
* Serverless 1.4+ installed on your workstation.

##Installation and deployment

1. Clone this repository
2. Copy __"example-configuration.yml"__ to __"configuration.yml"__ and set __AWS-region__, __AWS-hosted-zone-name__, and __AWS-DNS-address__ to appropriate values within __"configuration.yml"__.
3. Optional: change the DNS TTL in __"configuration.yml"__ to a value suitable to you.
4. Execute __"serverless deploy"__ to deploy the function to your AWS account.
5. Record the value of __DNSKey__ from the deployment output - this is your API key for access to the DNS update API.
6. Record the __endpoint__ address of the deployed API - this is the address you will be calling.
7. Call the API from the IP address that you want Dynamic DNS for (remembering to supply the API Key).

An example Linux curl command:

    curl -H "x-api-key: <your API key here>" -H "Content-Type: application/json" <your API endpoint address here>

##Using the EC2 Security Group update feature

When updating Route53 to point to your new IP address this function can also update EC2 security groups to switch ingress rules from the previous IP address to the new one.

To use this functionality you need to add a tag to the chosen security group(s) with the key of "DynamicProtocol" and a value of a comma separated TCP protocols to enable. For example:

     Key: "DynamicProtocol' 
     Value: 22,80



##Uninstallation

From your workstation execute __"serverless remove"__ to remove the function and API gateway from your AWS account - remember that the __AWS-region__ setting in __"configuration.yml"__ must match the API function that you want to remove.

OR - you could manually delete all of the AWS entities that have been created.


##Notes

In order to be able to deploy this function your current access to the AWS account must include :
*   All permissions required by your version of the Serverless framework to be able to deploy a lambda function + API Gateway
*   IAM permissions to be able to create a new IAM role that has access to Route53.

The deployment will set up its own IAM role that only has the minimum Route53 permissions required to perform the DNS updates - your administrative access will not be used by the API.


##TODO

* Make the Dynamic DNS address to be updated an API parameter to be supplied on each call (to enable the API to handle multiple DNS addresses)
* Add some simple Dynamic DNS client utils for different platforms.
* A whole bunch of bulletproofing for each API call.