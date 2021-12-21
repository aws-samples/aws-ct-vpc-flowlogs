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
import json
import boto3
import logging
import os
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)

session = boto3.Session()


def list_stack_instance_by_account(target_session, stack_set_name, account_id):
    '''
    List all stack instances based on the StackSet name and Account Id
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        cfn_paginator = cfn_client.get_paginator('list_stack_instances')
        operation_parameters = {
            'StackSetName': stack_set_name,
            'StackInstanceAccount': account_id
        }
        stackset_result = cfn_paginator.paginate(**operation_parameters)
        stackset_list = []

        for page in stackset_result:
            if 'Summaries' in page:
                stackset_list.extend(page['Summaries'])

        return stackset_list

    except Exception as e:
        LOGGER.error("List Stack Instance error: %s" % e)
        return []


def list_stack_instance_region(target_session, stack_set_name):
    '''
    List all stack instances based on the StackSet name
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        cfn_paginator = cfn_client.get_paginator('list_stack_instances')
        operation_parameters = {
            'StackSetName': stack_set_name
        }
        stackset_result = cfn_paginator.paginate(**operation_parameters)
        stackset_list_region = []

        for page in stackset_result:
            for instance in page['Summaries']:
                stackset_list_region.append(instance['Region'])

        stackset_list_region = list(set(stackset_list_region))

        return stackset_list_region

    except Exception as e:
        LOGGER.error("List Stack Instance error: %s" % e)
        return []


def create_stack_instance(target_session, stackset_name, account, regions):
    '''
    Create stackset in particular account + region
    '''
    try:
        cfn_client = target_session.client('cloudformation')
        response = cfn_client.create_stack_instances(
            StackSetName=stackset_name,
            Accounts=account,
            Regions=regions
        )
        LOGGER.debug(response)
        LOGGER.info("Launched stackset instance {} for account {} in regions: {} with Operation id: {}".format(
            stackset_name, account, regions, response["OperationId"]))
        return True
    except Exception as e:
        LOGGER.error("Could not create stackset instance : {}".format(e))
        return False


def get_accounts_by_ou(target_session, ou_id):
    '''
    List all active accounts by the OU id
    '''
    try:
        org_client = target_session.client('organizations')
        org_paginator = org_client.get_paginator('list_accounts_for_parent')
        operation_parameters = {
            'ParentId': ou_id
        }
        accounts_response = org_paginator.paginate(**operation_parameters)
        accounts_list = []
        active_accounts_list = []

        for page in accounts_response:
            if 'Accounts' in page:
                accounts_list.extend(page['Accounts'])

        for account in accounts_list:
            if account['Status'] == 'ACTIVE':
                active_accounts_list.append(account['Id'])

        return active_accounts_list

    except ClientError as e:
        LOGGER.error("Organization get accounts by OU error : {}".format(e))
        return []


def lambda_handler(event, context):
    LOGGER.info('Lambda Handler - Start')
    LOGGER.info('REQUEST RECEIVED: {}'.format(json.dumps(event, default=str)))

    # Check if lifecycle even matches
    if 'detail' in event and event['detail']['eventName'] == 'CreateManagedAccount':
        if event['detail']['serviceEventDetails']['createManagedAccountStatus']['state'] == 'SUCCEEDED':
            account_id = event['detail']['serviceEventDetails']['createManagedAccountStatus']['account']['accountId']

            # find if existing stackset instance for this account already exist
            stackset_name = (str(os.environ["stack_set_arn"]).split(":")[5]).split("/")[1]
            stackset_instances = list_stack_instance_by_account(session, stackset_name, account_id)
            stackset_instances_regions = list_stack_instance_region(session, stackset_name)

            # stackset instance does not exist, create a new one
            if len(stackset_instances) == 0:
                create_stack_instance(session, stackset_name, [account_id], stackset_instances_regions)

            # stackset instance already exist, check for missing region
            elif len(stackset_instances) > 0:
                stackset_region = []
                for instance in stackset_instances:
                    stackset_region.append(instance['Region'])
                next_region = list(set(stackset_instances_regions) - set(stackset_region))
                if len(next_region) > 0:
                    create_stack_instance(session, stackset_name, [account_id], next_region)
                else:
                    LOGGER.info("Stackset instance already exist : {}".format(stackset_instances))
        else:
            LOGGER.error("Invalid event state, expected: SUCCEEDED : {}".format(event))
    else:
        LOGGER.error("Invalid event received : {}".format(event))

    LOGGER.info('Lambda Handler - End')
