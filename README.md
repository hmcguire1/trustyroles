# Trustyroles
[![PyPI version](https://badge.fury.io/py/trustyroles.svg)](https://badge.fury.io/py/trustyroles)
[![PyPI license](https://img.shields.io/pypi/l/ansicolortags.svg)](https://pypi.python.org/pypi/ansicolortags/)

_An AWS Roles Toolkit_

Trusty Roles is intended to alleviate some of the painpoints I have dealt with in AWS automation leveraging boto3. 
The first version of this focuses on easily editing the assume role policy document of a role. 

#### Install
`pip install trustyroles`

### Assume Role Policy Update Module
#### Command Line Tool
#####  arpd_update
```
usage: arpd_update.py [-h] [-a ARN [ARN ...]] -u UPDATE_ROLE
                      [-m {get,update,remove}] [-e ADD_EXTERNAL_ID] [-r] [-j]
                      [-p] [-s SID]

optional arguments:
  -h, --help            show this help message and exit
  -a ARN [ARN ...], --arn ARN [ARN ...]
                        Add new ARNs to trust policy. Takes a comma-seperated
                        list of ARNS.
  -u UPDATE_ROLE, --update_role UPDATE_ROLE
                        Role for updating trust policy. Takes an role friendly
                        name as string.
  -m {get,update,remove}, --method {get,update,remove}
                        Takes choice of method to get, update, or remove.
  -e ADD_EXTERNAL_ID, --add_external_id ADD_EXTERNAL_ID
                        Takes an externalId as a string.
  -r, --remove_external_id
                        Method for removing externalId condition. Takes no
                        arguments
  -j, --json            Add to print json in get method.
  --retain_policy       Retain policy content when adding or deleting ARN in a
                        policy. Saves policy JSON in current directory as
                        policy.bk
  --add_sid ADD_SID     Add a Sid to trust policy. Takes a string.
  --remove_sid          Remove a Sid from a trust policy. Takes no arguments.
```
  
#### Example usage:
#### Get Policy
`arpd_update -m get -u 'test-role' --json`

###### Returns:
```
{
 "Action": "sts:AssumeRole",  
 "Condition": {},
 "Effect": "Allow",
 "Principal": {
  "AWS": ["arn:aws:iam:::user/test-role"]
 }
}
```
#### Using Python Modules
#####  arpd_update

#### Get Policy
```python
from trustyroles.arpd_update import arpd_update
arpd_update.get_arpd('test-role', json_flag=True)
```
###### Returns:
```
{  
 "Action": "sts:AssumeRole",  
 "Condition": {},
 "Effect": "Allow",
 "Principal": {
  "AWS": ["arn:aws:iam:::user/test-role"]
 }
}
```
#### Update Policy ARNS
The update_arn method takes a list of ARNS(arn_list) and a role_name to add to trust policy of suppplied role.

```python
from trustyroles.arpd_update import arpd_update
arpd_update.update_arn(["arn:aws:iam:::user/test-role2"], role_name='test-role')
```

####  Remove Policy ARNS
The remove_arn method takes a list of ARNS(arn_list) and a role_name to add to trust policy of suppplied role.

```python
from trustyroles.arpd_update import arpd_update
arpd_update.remove_arn(["arn:aws:iam:::user/test-role2"], role_name='test-role')
```

####  Add ExternalId
The add_external_id method takes an external_id and role_name as strings to allow the addition of an externalId condition.

```python
from trustyroles.arpd_update import arpd_update
arpd_update.add_external_id('<external_id>', role_name='test-role')
```

####  Remove ExternalId
The remove_external_id method takes a role_name as a string to allow the removal of an externalId condition.

```python
from trustyroles.arpd_update import arpd_update
arpd_update.remove_external_id(role_name='test-role')
```
#### Add Sid
Add a Sid to trust policy. Takes a string.
```python
from trustyroles.arpd_update import arpd_update
arpd_update.add_sid(role_name='test-role', sid='testRoleTempId')
```

#### Remove Sid
Remove a Sid from a trust policy. Takes no arguments.
```python
from trustyroles.arpd_update import arpd_update
arpd_update.remove_sid(role_name='test-role')
```

####  Retain Policy
Retain policy while making changes. Saves policy as JSON in current directory as policy.bk
```python
from trustyroles.arpd_update import arpd_update
arpd_update.retain_policy(role_name='test-role')
```