import os
import re
import logging
import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

def checkIP(event, context):

    # TODO ensure that function will create new recordset if required.
    # TODO add tests

    # Set up process variables
    action_message = ""
    error = False
    error_message = ""
    source_ip = ""
    source_ip_string = event["sourceip"]
    hosted_zone_name = os.environ["ZONE_NAME"]
    dns_address_string = os.environ["dns_address"]
    dns_ttl_string = os.environ["DNS_TTL"]

    LOGGER.info('Received event{}'.format(event))
    LOGGER.info('  Hosted Zone : ' + hosted_zone_name)
    LOGGER.info('  DNS address : ' + dns_address_string)
    LOGGER.info('  TTL value   : ' + dns_ttl_string)


    # Validate the supplied IP addresses
    if validate_ip(source_ip_string):
        source_ip = source_ip_string
    else:
        error = True
        error_message = "The source IP address valus is not valid - value is : " + source_ip_string
        LOGGER.error(error_message)

    # Validate the supplied DNS address
    if is_valid_hostname(dns_address_string):
        dns_address = add_trailing_dot(dns_address_string)
    else:
        error = True
        error_message = "The supplied DNS address is not a valid domain name" \
                         " - the supplied value is : " + \
                        dns_address_string
        LOGGER.error(error_message)

    # Validate the TTL value
    try:
        dns_ttl = int(dns_ttl_string)
    except ValueError:
        error = True
        error_message = "TTL value must be an integer - the supplied value is : " + dns_ttl_string
        LOGGER.error(error_message)

    if not error:
        r53_client = boto3.client('route53')

        r53_zone_response = r53_client.list_hosted_zones_by_name(DNSName=hosted_zone_name)

        if re.match('/hostedzone/.*', r53_zone_response['HostedZones'][0]['Id']) is not None:
            hosted_zone_id = r53_zone_response['HostedZones'][0]['Id'].split('/')[2]
        else:
            hosted_zone_id = r53_zone_response['HostedZones'][0]['Id']
    
        r53_recordset_response = r53_client.list_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            StartRecordName=dns_address)
    
        current_ip_value = ""
        for resource_record_set in r53_recordset_response["ResourceRecordSets"]:
            if resource_record_set["Name"] == dns_address_string:
                for val in resource_record_set["ResourceRecords"]:
                    current_ip_value = val["Value"]
    
        if current_ip_value <> source_ip:

            # Update any marked security groups
            modify_ec2_security_groups(source_ip, current_ip_value)

            # Now update Route 53
            action_message = "IP addresses differ - requesting update to Route53 DNS"
            update_response = r53_client.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    'Comment': 'Update to IP : ' + source_ip,
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': dns_address_string,
                                'Type': 'A',
                                'TTL': dns_ttl,
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
        else:
            action_message = "IP addresses match - no update required"

        LOGGER.info(action_message)

        body = {
            "message": action_message,
            "clientIP": source_ip,
            "ZoneId": hosted_zone_id,
            "currentIPset": current_ip_value
        }

        response = {
            "statusCode": 200,
            "body": body,
            "event": event
        }

        return response
    else:
        response = {
            "statusCode": 400,
            "errorMessage": error_message
        }
        return response


def add_trailing_dot(input_string):
    """Ensure that there is a trailing '.' on the string"""

    if len(input_string) > 0:
        if input_string[-1] <> ".":
            return input_string + "."
    return input_string

def modify_ec2_security_groups(new_IP, old_IP):
    """Modify any ec2 secgroups found to point to the new IP"""

    # Add the CIDR range to new & old IPs
    new_IP += '/32'
    old_IP += '/32'

    #Set up the boto3 ec2 client
    ec2 = boto3.client('ec2')

    # Find all of the security groups that are tagged for update
    group_list = ec2.describe_security_groups(
        Filters=[
            {
                'Name': 'tag-key',
                'Values': [
                    'DynamicProtocol'
                ]
            }
        ]
    )

    # For each SG found, read the tags to get the protocols that must be updated
    for sec_group in group_list['SecurityGroups']:
        for sg_tag in sec_group['Tags']:
            if sg_tag['Key'] == 'DynamicProtocol':

                protocol_revoke = []
                protocol_grant = []
                for sg_protocol in sg_tag['Value'].split(','):

                    # Only grant permission if it doesn't already exist
                    protocol_missing = True
                    for ip_permission in sec_group['IpPermissions']:
                        if ip_permission['FromPort'] == int(sg_protocol):
                            protocol_missing = False
                            grant_needed = True
                            for ip_range in ip_permission['IpRanges']:
                                if ip_range['CidrIp'] == new_IP:
                                    grant_needed = False
                            if grant_needed:
                                protocol_grant.append({
                                    'IpProtocol': 'tcp',
                                    'FromPort': int(sg_protocol),
                                    'ToPort': int(sg_protocol),
                                    'IpRanges': [
                                        {
                                            'CidrIp': new_IP
                                        }
                                    ]
                                })

                    # Grant access if no grants currently exist
                    if protocol_missing:
                        protocol_grant.append({
                            'IpProtocol': 'tcp',
                            'FromPort': int(sg_protocol),
                            'ToPort': int(sg_protocol),
                            'IpRanges': [
                                {
                                    'CidrIp': new_IP
                                }
                            ]
                        })

                    # Only issue a revoke if we find the IP/port combo
                    for ip_permission in sec_group['IpPermissions']:
                        if ip_permission['FromPort'] == int(sg_protocol):
                            for ip_range in ip_permission['IpRanges']:
                                if ip_range['CidrIp'] == old_IP:
                                    protocol_revoke.append({
                                        'IpProtocol': 'tcp',
                                        'FromPort': int(sg_protocol),
                                        'ToPort': int(sg_protocol),
                                        'IpRanges': [
                                            {
                                                'CidrIp': old_IP
                                            }
                                        ]
                                    })

            # Modify the security group
            if len(protocol_revoke) > 0:
                LOGGER.info('About to revoke on SG:' + sec_group['GroupId'])
                sg_revoke_response = ec2.revoke_security_group_ingress(
                    GroupId=sec_group['GroupId'],
                    IpPermissions=protocol_revoke)
            if len(protocol_grant) > 0:
                LOGGER.info('About to grant on SG:' + sec_group['GroupId'])
                sg_grant_response = ec2.authorize_security_group_ingress(
                    GroupId=sec_group['GroupId'],
                    IpPermissions=protocol_grant)


# The following functions have been borrowed
# from StackOverflow to validate the supplied DNS name

def is_valid_hostname(hostname):
    """Validate the supplied hostname"""

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

def validate_ip(ipv4_address):
    """Validate the supplied ip address"""

    octet_list = ipv4_address.split('.')
    if len(octet_list) != 4:
        return False
    for octet in octet_list:
        if not octet.isdigit():
            return False
        numeric_octet = int(octet)
        if numeric_octet < 0 or numeric_octet > 255:
            return False
    return True
