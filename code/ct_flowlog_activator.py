#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
from typing import Dict
import boto3
import os
import sys
import json
import logging
import uuid
import urllib3
import traceback
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

session = boto3.Session()
traffic_mode = ['DISABLE', 'REJECT', 'ACCEPT', 'ALL']
tag_keyword = str(os.environ['tag_keys']).replace(" ", "").split(",")
resource_type_map = {
    "vpc": "VPC",
    "subnet": "Subnet"
}
'''
Traffic mode:
3 = All traffic
2 = Accept traffic only
1 = Reject traffic only
0 = Disable
'''


def get_flow_log_status(target_session, accountId, resourceId, region):
    '''
    Get the VPC Flow Log status, takes VPC ID and Account ID
    '''
    try:
        ec2_client = target_session.client('ec2', region_name=region)
        response = ec2_client.describe_flow_logs(
            Filter=[
                {
                    'Name': 'resource-id',
                    'Values': [
                        resourceId,
                    ]
                },
            ],
        )

        flowlog_filter = 0
        for flowlog in response['FlowLogs']:
            if flowlog['LogDestinationType'] == 's3':
                flowlog_filter = get_flowlog_filter(flowlog['TrafficType'])

        return flowlog_filter

    except Exception as e:
        LOGGER.error("Could not describe Flow Log : {}".format(e), exc_info=True)


def get_flowlog_filter(traffic_type):
    switcher = {
        'ALL': 3,
        'ACCEPT': 2,
        'REJECT': 1,
        'DISABLE': 0
    }
    return switcher.get(traffic_type, -1)  # default no match will return -1 which is NONE


def parse_ec2_tag(tags):
    '''
    convert ec2 format tags to simpler dict
    '''
    try:
        simple_tags = {}
        if tags:
            for tag in tags:
                simple_tags[tag['Key']] = tag['Value']
        return simple_tags

    except Exception as e:
        LOGGER.error("Failed to parse EC2 tags: {}".format(e), exc_info=True)

def parse_flowlog_tag(tags, resource_type):
    '''
    Search for tags with key 'flowlog'.
    If no tags found on VPC, default to ALL traffic.
    If no tags found on Subnet, do nothing
    '''
    try:
        if resource_type == "VPC": 
            flowlog_tag = get_flowlog_filter(os.environ['default_traffic_to_log'])
        else: 
            flowlog_tag = -1
        
        if tags:
            for key, value in tags.items():
                if str.lower(key) in tag_keyword:
                    if str.lower(value) in str(os.environ['tag_all_values']).replace(" ", "").split(","):
                        flowlog_tag = 3
                    elif str.lower(value) in str(os.environ['tag_accept_values']).replace(" ", "").split(","):
                        flowlog_tag = 2
                    elif str.lower(value) in str(os.environ['tag_reject_values']).replace(" ", "").split(","):
                        flowlog_tag = 1
                    else:
                        flowlog_tag = 0
                    LOGGER.info("Found tag : {} = {}".format(key, value))
                    break

        return flowlog_tag
    except Exception as e:
        LOGGER.error("Failed to search Flow Log tag: {}".format(e), exc_info=True)


def toggle_flowlog(target_session, accountId, resourceId, resourceType, flowLogTag, flowLogStatus, region):
    '''
    Toggle the Flow Log based on the expected results from the flow log tag. Check against current status.
    '''
    try:
        if flowLogTag > 0 and flowLogStatus == 0:
            LOGGER.info("Activating Flow Log on acc: {} resourceId: {} with filter mode: {}".format(accountId, resourceId, traffic_mode[flowLogTag]))
            response = create_flowlog(target_session, accountId, resourceId, resourceType, traffic_mode[flowLogTag], os.environ['s3bucket'], region)
            if response:
                LOGGER.info("Flow Log activated : {}".format(response['FlowLogIds']))
            else:
                LOGGER.error("Failed to activate flow log on acc: {} resourceId: {} with filter mode: {}".format(
                    accountId, resourceId, traffic_mode[flowLogTag]))

        elif flowLogTag <= 0 and flowLogStatus > 0:
            LOGGER.info("Disabling Flow Log on acc: {} resourceId: {} with filter mode: {}".format(accountId, resourceId, traffic_mode[flowLogTag]))
            response = delete_flowlog(target_session, accountId, resourceId, region)
            if response:
                LOGGER.info("Flow Log deleted : {}".format(response['ResponseMetadata']))
            else:
                LOGGER.error("Failed to disable Flow Log on acc: {} resourceId: {} with filter mode: {}".format(
                    accountId, resourceId, traffic_mode[flowLogTag]))

        elif flowLogTag > 0 and flowLogStatus > 0:
            delta = abs(flowLogTag - flowLogStatus)
            if delta > 0:
                LOGGER.info("Changing Flow Log on acc: {} resourceId: {} with filter mode: {}".format(accountId, resourceId, traffic_mode[flowLogTag]))
                delete_response = delete_flowlog(target_session, accountId, resourceId, region)
                if delete_response:
                    LOGGER.debug("Original Flow Log deleted: {}".format(delete_response['ResponseMetadata']))
                else:
                    LOGGER.error("Failed to delete Flow Log on acc: {} resourceId: {} with filter mode: {}".format(
                        accountId, resourceId, traffic_mode[flowLogTag]))

                create_response = create_flowlog(target_session, accountId, resourceId, resourceType, traffic_mode[flowLogTag], os.environ['s3bucket'], region)
                if create_response:
                    LOGGER.info("Flow Log modified : {}".format(create_response['FlowLogIds']))
                else:
                    LOGGER.error("Failed to create flow log on acc: {} resourceId: {} with filter mode: {}".format(
                        accountId, resourceId, traffic_mode[flowLogTag]))

            else:
                LOGGER.info("No changes for Flow Log on acc: {} resourceId: {} with filter mode: {}".format(accountId, resourceId, traffic_mode[flowLogTag]))
        else:
            LOGGER.info("No changes for Flow Log on acc: {} resourceId: {} with filter mode: {}".format(accountId, resourceId, traffic_mode[flowLogTag]))

    except Exception as e:
        LOGGER.error("Failed to modify Flow Log : {}".format(e), exc_info=True)


def create_flowlog(target_session, accountId, resourceId, resourceType, trafficType, destinationBucket, region):
    '''
    Create Flow Log with destination S3, using the specified traffic type
    '''
    try:
        s3_location = 'arn:aws:s3:::' + destinationBucket + '/'
        ec2_client = target_session.client('ec2', region_name=region)
        response = ec2_client.create_flow_logs(
            ResourceIds=[resourceId],
            ResourceType=resourceType,
            TrafficType=trafficType,
            LogDestinationType='s3',
            LogDestination=s3_location
        )
        LOGGER.info('Flow Log details : {}'.format(response))
        if ('FlowLogIds' in response) and (len(response['FlowLogIds']) > 0):
            return response

    except Exception as e:
        LOGGER.error("Could not create Flow Log : {}".format(e), exc_info=True)


def delete_flowlog(target_session, accountId, resourceId, region):
    '''
    Delete the existing vpc flow log, only removes flow log with destination set to S3
    '''
    try:
        ec2_client = target_session.client('ec2', region_name=region)
        flowlogs = ec2_client.describe_flow_logs(
            Filter=[
                {
                    'Name': 'resource-id',
                    'Values': [
                        resourceId,
                    ]
                },
            ],
        )

        flowlog_ids = []
        for flowlog in flowlogs['FlowLogs']:
            if flowlog['LogDestinationType'] == 's3':
                flowlog_ids.append(flowlog['FlowLogId'])

        response = ec2_client.delete_flow_logs(
            FlowLogIds=flowlog_ids
        )
        if len(response['Unsuccessful']) > 0:
            LOGGER.error("Delete Flow Log Unsuccessful: {}".format(response))
        else:
            return response

    except Exception as e:
        LOGGER.error("Could not delete Flow Log : {}".format(e), exc_info=True)


def assume_role(aws_account_number, role_name, external_id):
    '''
    Assumes the provided role in each account and returns a session object
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call
    :return: Session object for the specified AWS Account and Region
    '''
    try:
        sts_client = boto3.client('sts')
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
        response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition, aws_account_number, role_name),
            RoleSessionName=str(aws_account_number + '-' + role_name),
            ExternalId=external_id
        )
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        LOGGER.info("Assumed session for {} - {}.".format(aws_account_number, role_name))
        return sts_session

    except Exception as e:
        LOGGER.error("Could not assume role : {}".format(e), exc_info=True)
        raise


def flow_log_handler(target_session, event, partition, resource_id, resource_type, tags, account_id, region):
    '''
    Handles the creation / deletion of vpc flow log, triggered by CloudWatch event Tag create / update / delete
    '''
    try:
        LOGGER.info('Target Account id: {}'.format(account_id))
        LOGGER.info('Target Region: {}'.format(region))
        LOGGER.info('Target Resource id: {}'.format(resource_id))
        LOGGER.info('Target Resource Type: {}'.format(resource_type))

        # Proceed to check FlowLog status
        flowlog_status = get_flow_log_status(target_session, account_id, resource_id, region)
        if flowlog_status > 0:
            LOGGER.info('Flow Logs currently enabled - Traffic Mode: {}'.format(traffic_mode[flowlog_status]))
        else:
            LOGGER.info('Flow Logs currently disabled')

        flowlog_tag = parse_flowlog_tag(tags, resource_type)
        toggle_flowlog(target_session, account_id, resource_id, resource_type, flowlog_tag, flowlog_status, region)

    except Exception as e:
        LOGGER.error('Error - reason: {}'.format(e), exc_info=True)


def get_vpc_by_region(target_session, accountId, region):
    '''
    Find all VPC in the region based on the account ID
    '''
    try:
        LOGGER.info(f'Getting list of accounts for {accountId} in region {region}')
        ec2_client = target_session.client('ec2', region_name=region)
        response = ec2_client.describe_vpcs(
            Filters=[
                {
                    'Name': 'owner-id',
                    'Values': [accountId]
                }
            ],
            MaxResults=10
        )
        vpc_list = response['Vpcs']

        LOGGER.debug(f'ec2_client.describe_vpcs returned: {json.dumps(vpc_list)}')
        while 'NextToken' in response:
            response = ec2_client.describe_vpcs(
                NextToken=response['NextToken']
            )
            vpc_list += response['Vpcs']

        if not vpc_list:
            LOGGER.info(f'No VPCs found for account {accountId}')

        return vpc_list

    except Exception as e:
        LOGGER.error("Could not describe VPC : {}".format(e), exc_info=True)
        return []


def get_subnet_by_region(target_session, accountId, region):
    '''
    Find all subnets in the region based on the account ID
    '''
    try:
        ec2_client = target_session.client('ec2', region_name=region)
        response = ec2_client.describe_subnets(
            Filters=[
                {
                    'Name': 'owner-id',
                    'Values': [accountId]
                }
            ],
            MaxResults=10
        )
        subnet_list = response['Subnets']

        while 'NextToken' in response:
            response = ec2_client.describe_subnets(
                NextToken=response['NextToken']
            )
            subnet_list += response['Subnets']

        if not subnet_list:
            LOGGER.info(f'No Subnets found for account {accountId}')
        return subnet_list

    except Exception as e:
        LOGGER.error("Could not describe Subnet : {}".format(e), exc_info=True)
        return []


def invoke_lambda(lambda_name, lambda_event, lambda_client, invoke_mode):
    '''
    Call Lambda function by the function name
    '''
    try:
        response = lambda_client.invoke(FunctionName=lambda_name, InvocationType=invoke_mode,
                                        Payload=bytes(json.dumps(lambda_event, default=str), encoding='utf8'))
        return response
    except ClientError as e:
        LOGGER.error(e.response['Error']['Message'] + ": " + lambda_name)


def list_stack_instance_by_region(target_session, stack_set_name, region):
    '''
    List all stack instances based on the StackSet name and region
    '''
    try:
        cfn_client = target_session.client('cloudformation', region_name=region)
        cfn_paginator = cfn_client.get_paginator('list_stack_instances')
        operation_parameters = {
            'StackSetName': stack_set_name
        }
        stackset_result = cfn_paginator.paginate(**operation_parameters)
        stackset_list = []

        for page in stackset_result:
            if 'Summaries' in page:
                stackset_list.extend(page['Summaries'])

        return stackset_list

    except Exception as e:
        LOGGER.error("List Stack Instance error: %s" % e, exc_info=True)
        return []


def lambda_handler(event, context):
    LOGGER.info('Lambda Handler - Start')
    LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))

    # If called from cloudformation as custom resource...
    if 'RequestType' in event:
        LOGGER.info("Using Cloudformation custom resource handler")
        cfn_handler(event, context)

    # Primary handler - takes cloudwatch timer and recursively call lambda for each accounts in the Org
    elif 'detail-type' in event and event['detail-type'] == 'Scheduled Event':
        LOGGER.info("Using CloudWatch Timer Handler")
        primary_handler(context)

    # Child handler - takes event from master Lambda, scan each active regions for VPCs
    elif 'child-thread' in event:
        LOGGER.info("Starting thread : {}".format(event['account']))
        child_handler(event, context)

    # Custom handler takes Event Bus from hub account for tag update at subnet and vpc level
    elif 'detail-type' in event and event['detail-type'] == 'Tag Change on Resource':
        LOGGER.info("Using Event Bus Handler")
        eventbridge_handler(event, context)

    else:
        LOGGER.error("Invalid event received : {}".format(event))
    LOGGER.info('Lambda Handler - End')


def eventbridge_handler(event, context):
    for key in event['detail']['changed-tag-keys']:
        if str.lower(key) in tag_keyword:
            partition = context.invoked_function_arn.split(":")[1]

            if event['detail']['resource-type'] in ['vpc', 'subnet']:
                for resource in event['resources']:
                    resource_id = resource.split(":")[5].split("/")[1]
                    account_id = event['account']
                    region = event['region']
                    tags = event['detail']['tags']
                    resource_type = resource_type_map[event['detail']['resource-type']]
                    target_session = assume_role(account_id, os.environ['assume_role'], os.environ['org_id'])
                    flow_log_handler(target_session, event, partition, resource_id, resource_type, tags, account_id, region)
        else:
            LOGGER.info("Skipping non supported tag: {}".format(key))


def cfn_handler(event, context):
    LOGGER.info('CFN Custom Resource - Received event {}'.format(event))
    if event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
        try:
            LOGGER.info(f"Spawning lambda in each account to setup VPC Flow Logs")
            primary_handler(context)
            LOGGER.info(f"Lambda's spawned successfully.")
            sendCfnResponse(event, context, "SUCCESS", {})
        except BaseException as error:
            LOGGER.info("exception while trying to spawn lambdas in each account")
            LOGGER.error(f"Error: ${error}")
            sendCfnResponse(event, context, "FAILED", {})
    elif event['RequestType'] == 'Delete':
        LOGGER.error(f"This CustomResource does nothing except for Create/Updates. Doing nothing now.")
        sendCfnResponse(event, context, "SUCCESS", {})


def child_handler(event, context):

    account_id = event['account']
    try:
        partition = context.invoked_function_arn.split(":")[1]

        region = region = str(context.invoked_function_arn).split(":")[3]
        target_session = assume_role(account_id, os.environ['assume_role'], os.environ['org_id'])

        vpc_ids = get_vpc_by_region(target_session, account_id, region)
        for vpc in vpc_ids:
            if 'Tags' in vpc:
                tags = parse_ec2_tag(vpc['Tags'])
                flow_log_handler(target_session, event, partition, vpc['VpcId'], 'VPC', tags, account_id, region)
            else:
                flow_log_handler(target_session, event, partition, vpc['VpcId'], 'VPC', {}, account_id, region)

        subnet_ids = get_subnet_by_region(target_session, account_id, region)
        for subnet in subnet_ids:
            if 'Tags' in subnet:
                tags = parse_ec2_tag(subnet['Tags'])
                flow_log_handler(target_session, event, partition, subnet['SubnetId'], 'Subnet', tags, account_id, region)
    except BaseException as error:
        LOGGER.error(f"Error while assuming role in {account_id} and attempting to alter vpc flow log settings: {error}")
        LOGGER.error('exception trace: ', exc_info=True)


def primary_handler(context):
    master_session = assume_role(os.environ['master_account'], os.environ['master_role'], os.environ['org_id'])

    # Look at stackset for existing deployment and do enforcement
    stackset_name = str(os.environ['stackset_name'])
    stackset_instances = list_stack_instance_by_region(master_session, stackset_name, os.environ['stackset_region'])
    account_list = []

    for instance in stackset_instances:
        account_list.append(instance['Account'])
    account_list = list(set(account_list))

    LOGGER.info("Accounts in stackset: {}".format(account_list))
    lambda_client = session.client('lambda')
    for account_id in account_list:
        worker_event = {}
        worker_event['child-thread'] = str(uuid.uuid1())
        worker_event['master-thread'] = context.aws_request_id
        worker_event['account'] = account_id
        response = invoke_lambda(str(context.function_name), worker_event, lambda_client, 'Event')
        LOGGER.info(f'primary_handler: executing child_handler for account {account_id}')
        LOGGER.debug(response)


def sendCfnResponse(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False, reason=None):
    responseUrl = event['ResponseURL']

    http = urllib3.PoolManager()

    print(responseUrl)

    responseBody = {
        'Status': responseStatus,
        'Reason': reason or "See the details in CloudWatch Log Stream: {}".format(context.log_stream_name),
        'PhysicalResourceId': physicalResourceId or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': noEcho,
        'Data': responseData
    }

    json_responseBody = json.dumps(responseBody)

    print("Response body:")
    print(json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = http.request('PUT', responseUrl, headers=headers, body=json_responseBody)
        print("Status code:", response.status)

    except Exception as e:

        print("send(..) failed executing http.request(..):", e)
