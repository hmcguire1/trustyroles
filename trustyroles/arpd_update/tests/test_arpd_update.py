import os
import json
import boto3  # type: ignore
from moto import mock_iam  # type: ignore
import pytest  # type: ignore
from trustyroles.arpd_update import arpd_update  # type: ignore

@pytest.fixture(scope='function')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'


initial_policy = {
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }
}


def create_role(policy: dict) -> None:
    boto3.client('iam').create_role(RoleName='test-123', 
                                    AssumeRolePolicyDocument=json.dumps(policy))


def delete_role():
    boto3.client('iam').delete_role(RoleName='test-123')


@mock_iam
def test_get_arpd():
    create_role()
    assert arpd_update.get_arpd(role_name="test-123") == initial_policy
    delete_role()


"""
@mock_iam
def test_add_external_id():
    create_role()
    assert arpd_update.add_external_id("123456", "test-123") == policy
    delete_role()


@mock_iam
def test_remove_external_id():
    create_role(policy=initial_policy)
    assert arpd_update.remove_external_id("123456", "test-123") == policy
   delete_role()
"""
