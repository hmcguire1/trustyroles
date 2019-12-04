# Trustyroles
_An AWS Roles Toolkit_

Trusty Roles is intended to alleviate some of the painpoints I have dealt with in AWS automation leveraging boto3. 
The first version of this focuses on easily editing the assume role policy document of a role. 

#### Install
`pip install trustyroles`

### Assume Role Policy Update Module
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

