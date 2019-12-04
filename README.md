# Trustyroles
_An AWS Roles Toolkit_

Trusty Roles is intended to alleviate some of the painpoints I have dealt with in AWS automation leveraging boto3. 
The first version of this focuses on easily editing the assume role policy document of a role. 
### Assume Role Policy Update Module
#### Command Line Tool
#####  arpd_update

-h, --help
Show this help message and exit

-a, --arn ARN[]
Add new ARNs to trust policy. Accepts multiple ARNS.

-u, --update_role UPDATE_ROLE
Role for updatget, ing trust policy. Takes an role friendly name as string.

-m,  --method [get, update, remove]
Takes choice of method to update, get, or remove.

-e, --add_external_id ADD_EXTERNAL_ID
Takes an external id as a string.

-r, --remove_external_id REMOVE_EXTERNAL_ID
Method for removing externalId condition. Takes no arguments

-j, --json
Add to print json in get method.
  
#### Example usage:
#### Get Policy
`ardp_update -m get -u 'test-role' --json`

###### Returns:

{
&nbsp;&nbsp;&nbsp;&nbsp; "Action": "sts:AssumeRole",  

&nbsp;&nbsp;&nbsp;&nbsp; "Condition": {},

&nbsp;&nbsp;&nbsp;&nbsp; "Effect": "Allow",

&nbsp;&nbsp;&nbsp;&nbsp; "Principal": {

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; "AWS": ["arn:aws:iam:::user/test-role"]

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; }

}

#### Using Python Modules
#####  arpd_update

#### Get Policy
```
from trustyroles.arpd_update import arpd_update
arpd_update.get_arpd('test-role', json_flag=True)
```
###### Returns:
{

&nbsp;&nbsp; "Action": "sts:AssumeRole",  

&nbsp;&nbsp;&nbsp;&nbsp; "Condition": {},

&nbsp;&nbsp;&nbsp;&nbsp; "Effect": "Allow",

&nbsp;&nbsp;&nbsp;&nbsp; "Principal": {

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; "AWS": ["arn:aws:iam:::user/test-role"]

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; }

}
