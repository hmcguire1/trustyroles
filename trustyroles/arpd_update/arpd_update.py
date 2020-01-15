"""
arpd_update focuses on easily editing the assume role policy document of a role.
"""
import os
import json
import logging
import argparse

from typing import List, Dict
import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore

LOGGER = logging.getLogger('IAM-ROLE-TRUST-POLICY')
logging.basicConfig(level=logging.WARNING)
PARSER = argparse.ArgumentParser()

def _main():
    """The _main method can take in a list of ARNs, role to update,
        and method [get, update, remove]."""
    PARSER.add_argument(
        '-a', '--arn',
        nargs='+',
        required=False,
        help='Add new ARNs to trust policy. Takes a comma-seperated list of ARNS.'
    )

    PARSER.add_argument(
        '-u', '--update_role',
        type=str,
        required=True,
        help='Role for updating trust policy. Takes an role friendly name as string.'
    )

    PARSER.add_argument(
        '-m', '--method',
        type=str,
        required=False,
        choices=['get', 'update', 'remove'],
        help='Takes choice of method to get, update, or remove.'
    )

    PARSER.add_argument(
        '-e', '--add_external_id',
        type=str,
        required=False,
        help='Takes an externalId as a string.'
    )

    PARSER.add_argument(
        '-r', '--remove_external_id',
        help='Method for removing externalId condition. Takes no arguments'
    )

    PARSER.add_argument(
        '-j', '--json',
        action='store_true',
        required=False,
        help='Add to print json in get method.'
    )

    PARSER.add_argument(
        '--retain_policy',
        action='store_true',
        required=False,
        help='''Retain policy content when adding or deleting ARN in a policy.
        Saves policy JSON in current directory as policy.bk'''
    )

    PARSER.add_argument(
        '--add_sid',
        required=False,
        help='Add a Sid to trust policy. Takes a string.'
    )

    PARSER.add_argument(
        '--remove_sid',
        action='store_true',
        required=False,
        help='Remove a Sid from a trust policy. Takes no arguments.'
    )

    args = vars(PARSER.parse_args())

    if args['method'] == 'update':
        arpd = update_arn(
            args['arn'],
            args['update_role']
        )
        print(json.dumps(arpd['Statement'][0], indent=4))
    elif args['method'] == 'remove':
        arpd = remove_arn(
            args['arn'],
            args['update_role']
        )
        print(json.dumps(arpd['Statement'][0], indent=4))
    elif args['method'] == 'get':
        arpd = get_arpd(
            args['update_role'],
        )
        if args['json']:
            print(json.dumps(arpd['Statement'][0], indent=4))
        else:
            print(f"\nARNS:")
            if isinstance(arpd['Statement'][0]['Principal']['AWS'], list):
                for arn in arpd['Statement'][0]['Principal']['AWS']:
                    print(f"  {arn}")
            else:
                print(f"  {arpd['Statement'][0]['Principal']['AWS']}")
            print(f"Conditions:")
            if arpd['Statement'][0]['Condition']:
                print(f"  {arpd['Statement'][0]['Condition']}")

    if args['add_external_id'] is not None:
        arpd = add_external_id(
            external_id=args['add_external_id'],
            role_name=args['update_role']
        )
        print(json.dumps(arpd['Statement'][0], indent=4))
    if args['remove_external_id']:
        arpd = remove_external_id(
            role_name=args['update_role']
        )
        print(json.dumps(arpd['Statement'][0], indent=4))
    if args['retain_policy']:
        arpd = retain_policy(role_name=args['update_role'])
        print(json.dumps(arpd['Statement'][0], indent=4))
    if args['add_sid']:
        arpd = add_sid(role_name=args['update_role'], sid=args['add_sid'])
        print(json.dumps(arpd['Statement'][0], indent=4))
    if args['remove_sid']:
        arpd = remove_sid(role_name=args['update_role'])
        print(arpd['Statement'][0])
        print(json.dumps(arpd['Statement'][0], indent=4))


def get_arpd(role_name: str, client=None) -> Dict:
    """The get_arpd method takes in a role_name as a string
    and provides trusted ARNS and Conditions."""
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    return role['Role']['AssumeRolePolicyDocument']

def add_external_id(external_id: str, role_name: str, client=None) -> Dict:
    """The add_external_id method takes an external_id and role_name as strings
        to allow the addition of an externalId condition."""
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    arpd['Statement'][0]['Condition'] = {'StringEquals': {'sts:ExternalId': external_id}}

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )
        return arpd
    except ClientError as ex:
        raise ex

def remove_external_id(role_name: str, client=None) -> Dict:
    """The remove_external_id method takes a role_name as a string
        to allow the removal of an externalId condition."""
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    arpd['Statement'][0]['Condition'] = {}

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )
        return arpd
    except ClientError as ex:
        raise ex

def update_arn(arn_list: List, role_name: str, client=None) -> Dict:
    """The update_arn method takes a list of ARNS(arn_list) and a role_name
        to add to trust policy of suppplied role."""
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']
    old_principal_list = arpd['Statement'][0]['Principal']['AWS']

    for arn in arn_list:
        if arn not in old_principal_list:
            if isinstance(old_principal_list, list):
                for old_arn in arn_list:
                    old_principal_list.append(old_arn)
                arpd['Statement'][0]['Principal']['AWS'] = old_principal_list
            else:
                new_principal_list = []
                for old_arn in arn_list:
                    new_principal_list.append(old_arn)
                new_principal_list.append(old_principal_list)
                arpd['Statement'][0]['Principal']['AWS'] = new_principal_list

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )
        return arpd
    except ClientError as ex:
        raise ex

def remove_arn(arn_list: List, role_name: str, client=None) -> Dict:
    """The remove_arn method takes in a string or list of ARNs and a role_name
        to remove ARNS from trust policy of supplied role."""
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']
    old_principal_list = arpd['Statement'][0]['Principal']['AWS']

    if isinstance(arn_list, list):
        for arn in arn_list:
            if arn in old_principal_list:
                old_principal_list.remove(arn)
    else:
        old_principal_list.remove(arn_list)

    arpd['Statement'][0]['Principal']['AWS'] = old_principal_list

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )
        return arpd
    except ClientError as ex:
        raise ex

def retain_policy(role_name: str, client=None) -> Dict:
    """
    The retain_policy method creates a backup of previous
    policy in current directory as policy.bk
    """
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    with open(os.getcwd() + '/policy.bk', "w") as file:
        json.dump(arpd, file)

    return arpd

def add_sid(role_name: str, sid: str, client=None) -> Dict:
    """
    The add_sid method adds a statement ID to
    the assume role policy document
    """
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    arpd['Statement'][0]['Sid'] = sid

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )
        return arpd
    except ClientError as ex:
        raise ex

def remove_sid(role_name: str, client=None) -> Dict:
    """
    The remove_sid method removes the statement ID
    from the assume role policy document
    """
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    if arpd['Statement'][0]['Sid'] is not None:
        arpd['Statement'][0].pop('Sid')
        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(arpd)
            )
        except ClientError as ex:
            raise ex
    return arpd


if __name__ == "__main__":
    _main()
