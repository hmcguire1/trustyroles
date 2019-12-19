import json
import logging
import argparse
import os
import typing
import boto3
from botocore.exceptions import ClientError


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
        update_arn(
            args['arn'],
            args['update_role']
        )
    elif args['method'] == 'remove':
        remove_arn(
            args['arn'],
            args['update_role']
        )
    elif args['method'] == 'get':
        if args['json']:
            get_arpd(
                args['update_role'],
                json_flag=True
            )
        else:
            get_arpd(
                args['update_role']
            )

    if args['add_external_id'] is not None:
        add_external_id(
            external_id=args['add_external_id'],
            role_name=args['update_role']
        )
    if args['remove_external_id']:
        remove_external_id(
            role_name=args['update_role']
        )
    if args['retain_policy']:
        retain_policy(role_name=args['update_role'])

    if args['add_sid']:
        add_sid(role_name=args['update_role'], sid=args['add_sid'])

    if args['remove_sid']:
        remove_sid(role_name=args['update_role'])


def get_arpd(role_name: str, json_flag: bool = False, client: object = None) -> None:
    """The get_arpd method takes in a role_name as a string
    and provides trusted ARNS and Conditions."""
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    if json_flag:
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

def add_external_id(external_id: str, role_name: str, client: object = None) -> None:
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

        print(json.dumps(arpd['Statement'][0], indent=4))
    except ClientError as error:
        print(error)

def remove_external_id(role_name: str, client: object = None) -> None:
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

        print(json.dumps(arpd['Statement'][0], indent=4))
    except ClientError as error:
        print(error)

def update_arn(arn_list: str, role_name: str, client: object = None) -> None:
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
        print(json.dumps(arpd['Statement'][0], indent=4))
    except ClientError as error:
        print(error)

def remove_arn(arn_list: str, role_name: str, client: object = None) -> None:
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
        print(json.dumps(arpd['Statement'][0], indent=4))
    except ClientError as error:
        print(error)

def retain_policy(role_name: str, client: object = None) -> None:
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

def add_sid(role_name: str, sid: str, client: object = None) -> None:
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
        print(json.dumps(arpd['Statement'][0], indent=4))
    except ClientError as error:
        print(error)

def remove_sid(role_name: str, client: object = None) -> None:
    if client:
        iam_client = client.client('iam')
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    if arpd['Statement'][0]['Sid'] is not None:
        arpd['Statement'][0].pop('Sid')
        print(arpd['Statement'][0])

        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(arpd)
            )
            print(json.dumps(arpd['Statement'][0], indent=4))
        except ClientError as error:
            print(error)

if __name__ == "__main__":
    _main()
