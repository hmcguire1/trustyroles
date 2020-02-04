"""
arpd_update focuses on easily editing the assume role policy document of a role.
"""
import os
import json
import logging
import argparse
from datetime import datetime

from typing import List, Dict, Optional
import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore

LOGGER = logging.getLogger('IAM-ROLE-TRUST-POLICY')
logging.basicConfig(level=logging.WARNING)
PARSER = argparse.ArgumentParser()

def _main():
    """The _main method can take in a list of ARNs, role to update,
        and method [get, update, remove, restore]."""
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
        choices=['get', 'update', 'remove', 'restore'],
        help='Takes choice of method to get, update, or remove.'
    )

    PARSER.add_argument(
        '-e', '--add_external_id',
        type=str,
        required=False,
        help='Takes an externalId as a string.'
    )

    PARSER.add_argument(
        '--remove_external_id',
        action='store_true',
        required=False,
        help='Method for removing externalId condition. Takes no arguments'
    )

    PARSER.add_argument(
        '--json',
        action='store_true',
        required=False,
        help='Add to print json in get method.'
    )

    PARSER.add_argument(
        '--add_sid',
        type=str,
        required=False,
        help='Add a Sid to trust policy. Takes a string.'
    )

    PARSER.add_argument(
        '--remove_sid',
        action='store_true',
        required=False,
        help='Remove a Sid from a trust policy. Takes no arguments.'
    )

    PARSER.add_argument(
        '--backup_policy',
        type=str,
        required=False,
        help='''Creates a backup of previous policy
    in current directory as <ISO-time>.policy.bk'''
    )

    PARSER.add_argument(
        '--dir_path',
        type=str,
        required=False,
        help='Path to directory for backup policy. Takes a string'
    )

    PARSER.add_argument(
        '--file_path',
        type=str,
        required=False,
        help='File for backup policy. Takes a string'
    )

    PARSER.add_argument(
        '--bucket',
        type=str,
        required=False,
        help='S3 bucket name for backup policy. Takes a string'
    )

    PARSER.add_argument(
        '--key',
        type=str,
        required=False,
        help='S3 key name for restoring S3 policy. Takes a string'
    )

    args = vars(PARSER.parse_args())

    if args['backup_policy']:
        if args['backup_policy'] == 'local':
            if args['dir_path']:
                dir_path = args['dir_path']
            else:
                dir_path = os.getcwd()

            bucket = None
        elif args['backup_policy'] == 's3':
            bucket = args['bucket']
            dir_path = None
    else:
        dir_path = os.getcwd()
        bucket = ''

    if args['method'] == 'update':
        arpd = update_arn(
            args['arn'],
            args['update_role'],
            dir_path=dir_path,
            bucket=bucket,
            backup_policy=args['backup_policy']
        )

        print(json.dumps(arpd['Statement'][0], indent=4))
    elif args['method'] == 'remove':
        arpd = remove_arn(
            args['arn'],
            args['update_role'],
            dir_path=dir_path,
            bucket=bucket,
            backup_policy=args['backup_policy']
        )

        print(json.dumps(arpd['Statement'][0], indent=4))
    elif args['method'] == 'get':
        arpd = get_arpd(
            args['update_role']
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

    elif args['method'] == 'restore' and args['backup_policy']:
        if args['backup_policy'].lower() == 'local' and args['file_path']:
            arpd = restore_from_backup(
                role_name=args['update_role'],
                location_type='local',
                file_path=args['file_path']
            )
        elif args['backup_policy'].lower() == 's3': 
            arpd = restore_from_backup(
                role_name=args['update_role'],
                location_type='s3',
                file_path='',
                key=args['key'],
                bucket=bucket,
                backup_policy=args['backup_policy']
            )

        print(json.dumps(arpd['Statement'][0], indent=4))

    if args['add_external_id']:
        arpd = add_external_id(
            external_id=args['add_external_id'],
            role_name=args['update_role'],
            dir_path=dir_path,
            bucket=bucket,
            backup_policy=args['backup_policy']
        )

        print(json.dumps(arpd['Statement'][0], indent=4))

    if args['remove_external_id']:
        arpd = remove_external_id(
            role_name=args['update_role'],
            dir_path=dir_path,
            bucket=bucket,
            backup_policy=args['backup_policy']
        )

        print(json.dumps(arpd['Statement'][0], indent=4))

    if args['add_sid']:
        arpd = add_sid(
            role_name=args['update_role'],
            sid=args['add_sid'],
            dir_path=dir_path,
            bucket=bucket,
            backup_policy=args['backup_policy']
        )

        print(json.dumps(arpd['Statement'][0], indent=4))

    if args['remove_sid']:
        arpd = remove_sid(
            role_name=args['update_role'],
            dir_path=dir_path,
            bucket=bucket,
            backup_policy=args['backup_policy']
        )

        print(json.dumps(arpd['Statement'][0], indent=4))

def get_arpd(role_name: str, session=None, client=None) -> Dict:
    """The get_arpd method takes in a role_name as a string
    and provides trusted ARNS and Conditions.
    """

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)

    return role['Role']['AssumeRolePolicyDocument']

def update_arn(role_name: str, arn_list: List, dir_path: Optional[str], client=None,
               session=None, backup_policy: Optional[str] = '', 
               bucket: Optional[str] = None) -> Dict:
    """The update_arn method takes a multiple ARNS(arn_list) and a role_name
        to add to trust policy of suppplied role.
    """

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']
    old_principal_list = arpd['Statement'][0]['Principal']['AWS']

    if backup_policy:
        if backup_policy.lower() == 'local':
            if dir_path:
                retain_policy(policy=arpd, role_name=role_name, location_type='local',
                            dir_path=dir_path)
            else:
                retain_policy(policy=arpd, role_name=role_name, location_type='local')
        elif backup_policy.lower() == 's3':
            retain_policy(policy=arpd, role_name=role_name, location_type='s3',
                        bucket=bucket)

    if isinstance(old_principal_list, list):
        for arn in arn_list:
            arpd['Statement'][0]['Principal']['AWS'].append(arn)
    else:
        old_principal_list = [old_principal_list]

        for arn in arn_list:
            arpd['Statement'][0]['Principal']['AWS'] = old_principal_list
            arpd['Statement'][0]['Principal']['AWS'].append(arn)

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )

        return arpd

    except ClientError as error:
        raise error

def remove_arn(role_name: str, arn_list: List, dir_path: Optional[str], session=None,
               client=None, backup_policy: Optional[str] = '',
               bucket: Optional[str] = None) -> Dict:
    """The remove_arn method takes in a string or multiple of ARNs and a role_name
        to remove ARNS from trust policy of supplied role.
    """

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']
    old_principal_list = arpd['Statement'][0]['Principal']['AWS']

    if backup_policy:
        if backup_policy.lower() == 'local':
            if dir_path:
                retain_policy(policy=arpd, role_name=role_name, location_type='local',
                            dir_path=dir_path)
            else:
                retain_policy(policy=arpd, role_name=role_name, location_type='local')
        elif backup_policy.lower() == 's3':
            retain_policy(policy=arpd, role_name=role_name, location_type='s3',
                        bucket=bucket)

    for arn in arn_list:
        if arn in old_principal_list:
            arpd['Statement'][0]['Principal']['AWS'].remove(arn)

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )

        return arpd

    except ClientError as error:
        raise error

def add_external_id(role_name: str, external_id: str, dir_path: Optional[str],
                    client=None, session=None, backup_policy: Optional[str] = '',
                    bucket: Optional[str] = None) -> Dict:
    """
    The add_external_id method takes an external_id and role_name as strings
    to allow the addition of an externalId condition.
    """

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    if backup_policy:
        if backup_policy.lower() == 'local':
            if dir_path:
                retain_policy(policy=arpd, role_name=role_name, location_type='local',
                            dir_path=dir_path)
            else:
                retain_policy(policy=arpd, role_name=role_name, location_type='local')
        elif backup_policy.lower() == 's3':
            retain_policy(policy=arpd, role_name=role_name, location_type='s3',
                        bucket=bucket)

    arpd['Statement'][0]['Condition'] = {'StringEquals': {'sts:ExternalId': external_id}}

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )

        return arpd

    except ClientError as error:
        raise error

def remove_external_id(role_name: str, dir_path: Optional[str], session=None,
                       client=None, backup_policy: Optional[str] = '',
                       bucket: Optional[str] = None) -> Dict:
    """The remove_external_id method takes a role_name as a string
        to allow the removal of an externalId condition.
    """

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    if backup_policy:
        if backup_policy.lower() == 'local':
            if dir_path:
                retain_policy(policy=arpd, role_name=role_name, location_type='local',
                            dir_path=dir_path)
            else:
                retain_policy(policy=arpd, role_name=role_name, location_type='local')
        elif backup_policy.lower() == 's3':
            retain_policy(policy=arpd, role_name=role_name, location_type='s3',
                        bucket=bucket)

    arpd['Statement'][0]['Condition'] = {}

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )

        return arpd

    except ClientError as error:
        raise error

def add_sid(role_name: str, sid: str, dir_path: Optional[str], session=None,
            client=None, backup_policy: Optional[str] = '',
            bucket: Optional[str] = None) -> Dict:
    """
    The add_sid method adds a statement ID to
    the assume role policy document
    """

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    if backup_policy:
        if backup_policy.lower() == 'local':
            if dir_path:
                retain_policy(policy=arpd, role_name=role_name, location_type='local',
                            dir_path=dir_path)
            else:
                retain_policy(policy=arpd, role_name=role_name, location_type='local')
        elif backup_policy.lower() == 's3':
            retain_policy(policy=arpd, role_name=role_name, location_type='s3',
                        bucket=bucket)

    arpd['Statement'][0]['Sid'] = sid

    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(arpd)
        )

        return arpd

    except ClientError as ex:
        raise ex

def remove_sid(role_name: str, dir_path: Optional[str], session=None,
               client=None, backup_policy: Optional[str] = '',
               bucket: Optional[str] = None) -> Dict:
    """
    The remove_sid method removes the statement ID
    from the assume role policy document
    """

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    role = iam_client.get_role(RoleName=role_name)
    arpd = role['Role']['AssumeRolePolicyDocument']

    if backup_policy.lower() == 'local':
        if dir_path:
            retain_policy(policy=arpd, role_name=role_name, location_type='local',
                          dir_path=dir_path)
        else:
            retain_policy(policy=arpd, role_name=role_name, location_type='local')
    elif backup_policy.lower() == 's3':
        retain_policy(policy=arpd, role_name=role_name, location_type='s3',
                      bucket=bucket)

    if arpd['Statement'][0]['Sid']:
        arpd['Statement'][0].pop('Sid')

        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(arpd)
            )
        except ClientError as error:
            raise error

    return arpd

def retain_policy(role_name: str, policy: Dict, session=None, client=None,
                  location_type: Optional[str] = None,
                  dir_path=os.getcwd(), bucket: Optional[str] = None) -> None:
    """
    The retain_policy method creates a backup of previous
    policy in current directory by default as <ISO-time>.<RoleName>.bk or specified directory
    for local file or with s3 to specified bucket and key name.
    """

    if location_type.lower() == 'local':
        with open(dir_path + '/' + datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                  + f".{role_name}.bk", "w") as file:
            json.dump(policy, file, ensure_ascii=False, indent=4)
            
    elif location_type.lower() == 's3':
        if session:
            s3_client = session.client('s3')
        elif client:
            s3_client = client
        else:
            s3_client = boto3.client('s3')

        try:
            s3_client.put_object(
                Bucket=bucket,
                Key=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                + f".{role_name}.bk",
                Body=json.dumps(policy).encode()
            )
        except ClientError as error:
            raise error

def restore_from_backup(role_name: str, location_type: str, session=None,
                        client=None, bucket: Optional[str] = None, 
                        key: Optional[str] = None,
                        file_path: Optional[str] = None) -> None:

    if session:
        iam_client = session.client('iam')
    elif client:
        iam_client = client
    else:
        iam_client = boto3.client('iam')

    if location_type.lower() == 'local':
        with open(file_path, 'r') as file:
            policy = file.read()

        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=policy
        )
    elif location_type.lower() == 's3':
        if session:
            s3_client = session.client('s3')
        else:
            s3_client = boto3.client('s3')

        filename = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ") + f".{role_name}.dl"

        s3_client.download_file(
            Bucket=bucket,
            Key=key,
            Filename=filename
        )

        with open(filename, 'rb') as file:
            policy = file.read().decode()
        os.remove(filename)
    

    iam_client.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=policy
    )

    return json.loads(policy)


if __name__ == '__main__':
    _main()
