# Trustyroles
--- 
<br />

## An AWS Roles Toolkit
>### Assume Role Policy Update Module

### Command Line Tool
###  arpd_update
<br />

-h [-a ARN [ARN ...]]
-u UPDATE_ROLE
                  -m [update, remove, get]
                  -e ADD_EXTERNAL_ID
                  -r REMOVE_EXTERNAL_ID 
              
-j JSON_FLAG

optional arguments:
  -h, --help            show this help message and exit
  -a ARN [ARN ...], --arn ARN [ARN ...]
                        Add new ARNs to trust policy. Takes a comma-seperated
                        list of ARNS.
  -u UPDATE_ROLE, --update_role UPDATE_ROLE
                        Role for updating trust policy. Takes an role friendly
                        name as string.
  -m {update,remove,get}, --method {update,remove,get}
                        Takes choice of method to update, get, or remove.
  -e ADD_EXTERNAL_ID, --add_external_id ADD_EXTERNAL_ID
                        Takes an external id as a string.
  -r REMOVE_EXTERNAL_ID, --remove_external_id REMOVE_EXTERNAL_ID
                        Method for removing externalId condition. Takes no
                        arguments
  -j, --json            Add to print json in get method.
  
#### Example usage:
#### Get Policy
`ardp_update -m get -u 'test-role' --json`

{
&nbsp;&nbsp;&nbsp; &nbsp;"Action": "sts:AssumeRole",
&nbsp;&nbsp;&nbsp;&nbsp; "Condition": {},
&nbsp;&nbsp;&nbsp;&nbsp; "Effect": "Allow",
&nbsp;&nbsp;&nbsp;&nbsp; "Principal": {
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; "AWS": ["arn:aws:iam:::user/test-role"]
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; }
}
