import json
import boto3
import os
import re 

def checkIP(event, context):

    # TODO Add trailing '.' if missing
    # TODO ensure that function will create new recordset if required.
    # TODO add API key
    # TODO Validate all values
    # TODO add tests

    # Set up process variables
    error = False
    error_message = ""
    source_ip = ""
    source_ip_string = event["sourceip"]
    hosted_zone_name = os.environ["ZONE_NAME"]
    dns_address_string = os.environ["DNS_ADDRESS"]
    dns_ttl_string = os.environ["DNS_TTL"]

    # Validate the supplied IP addresses
    if validate_ip(source_ip_string):
        source_ip = source_ip_string
    else:
        error = True
        error_message = "The source IP address valus is not valid - value is : " + source_ip_string

    # Validate the supplied DNS address
    if is_valid_hostname(dns_address_string):
        DNSaddress = dns_address_string
    else:
        error = True
        error_message = "The supplied DNS address is not a valid domain name - the supplied value is : " + dns_address_string

    # Validate the TTL value
    try:
        DNSTTL = int(dns_ttl_string)
    except ValueError:
        error = True
        error_message = "TTL value must be an integer - the supplied value is : " + dns_ttl_string

    if not error:

        r53_client = boto3.client('route53')

        r53_zone_response = r53_client.list_hosted_zones_by_name(DNSName=hosted_zone_name)

        hosted_zone_id = r53_zone_response['HostedZones'][0]['Id'].split('/')[2]
    
        r53_recordset_response = r53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id, StartRecordName=DNSaddress)
    
        found = "No"
        CurrentIPValue = ""
        for RRS in r53_recordset_response["ResourceRecordSets"]:
            if RRS["Name"] == dns_address_string:
                found = "Yes"
                for val in RRS["ResourceRecords"]:
                    CurrentIPValue = val["Value"]
    
        
        # TODO Validate that values are valid IPv4 addresses 
    
        updateRequired = "No"
        updateResponse = ""
        if CurrentIPValue <> source_ip:
            updateRequired = "Yes"
            updateResponse = r53_client.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    'Comment': 'Update to IP : ' + source_ip,
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': dns_address_string + '.',
                                'Type': 'A',
                                'TTL': DNSTTL,
                                'ResourceRecords': [
                                    {
                                        'Value': source_ip
                                    }
                                ]
                            }
                        }
                    ]
                }
            )
    
            # TODO add error handling
    
    
        body = {
            "message": "Received IP address",
            "clientIP": source_ip,
            "ZoneId": hosted_zone_id,
            "currentIPset": CurrentIPValue,
            "zone response": r53_zone_response,
            "recordsets" : json.dumps(r53_recordset_response),
            "found": found,
            "updateRequired": updateRequired
        }
    
    
        response = {
            "statusCode": 200,
            "body": json.dumps(body),
            "event": json.dumps(event)
        }
        
        return response


    # The following functions have been borrowed from StackOverflow to validate the supplied DNS name

def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels) 

def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True