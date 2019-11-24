import json
import logging
import argparse
import boto3

LOGGER = logging.getLogger('IAM-Policy-Update')
logging.basicConfig(level=logging.INFO)
PARSER = argparse.ArgumentParser()

# Main method takes in list of ARNs, role to update, and method [update, remove].
def _main():
    PARSER.add_argument(
        '-a', '--arn',
        type=list,
        nargs='+',
        required=True,
        help='Add new ARNs to trust policy. Takes a list of ARNS.'
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
        required=True,
        choices=['update', 'remove'],
        help='Takes choice of method to update or remove.'
    )

    args = vars(PARSER.parse_args())

    if args['method'] == 'update':
        update_arn(
            args['arn'],
            args['update_role']
        )
    else:
        remove_arn(
            args['arn'],
            args['update_role']
        )

def get_arpd(role_name):
    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    ardp = role.get('Role', {}).get('AssumeRolePolicyDocument', {})

    print(f"\nARNS:")
    for arn in ardp['Statement'][0]['Principal']['AWS']:
        print(f"  {arn}")
    print(f"Conditions:")
    

# Update method takes a list of ARNS and a role name to add to trust policy of suppplied role.
def update_arn(arn_list, role_name):

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    ardp = role.get('Role', {}).get('AssumeRolePolicyDocument', {})
    old_principal_list = ardp['Statement'][0]['Principal']['AWS']

    for arn in arn_list:
        if arn not in old_principal_list:
            if isinstance(old_principal_list, list):
                new_principal_list = [old_principal_list.append(arn) for arn in arn_list]
            else:
                new_principal_list = []
                for arn in arn_list:
                    new_principal_list.append(arn)
                new_principal_list.append(old_principal_list)

    ardp['Statement'][0]['Principal']['AWS'] = new_principal_list

    for arn in arn_list:
        LOGGER.info("Updating Policy to add: '%s'", arn)

    iam_client.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(ardp)
    )
# Remove method takes a list of ARNS and a role name to re,pve from trust policy of supplied role.
def remove_arn(arn_list, role_name):

    iam_client = boto3.client('iam')
    role = iam_client.get_role(RoleName=role_name)
    ardp = role.get('Role', {}).get('AssumeRolePolicyDocument', {})
    old_principal_list = ardp['Statement'][0]['Principal']['AWS']
    for arn in arn_list:
        if arn in old_principal_list:
            old_principal_list.remove(arn)

    ardp['Statement'][0]['Principal']['AWS'] = old_principal_list

    for arn in arn_list:
        LOGGER.info("Updating Policy to remove: '%s'", arn)

    iam_client.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(ardp)
    )

if __name__ == "__main__":
    _main()
