import moto  # type: ignore
import pytest  # type: ignore
from trustyroles.arpd_update import arpd_update  # type: ignore

mock_aws_account = moto.mock_iam()
mock_aws_account.start()

initial_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["arn:aws:iam:::user/test-role1"]},
            "Action": "sts:AssumeRole",
        }
    ],
}

policy_with_added_sid = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "1",
            "Condition": {},
            "Effect": "Allow",
            "Principal": {"AWS": ["arn:aws:iam:::user/test-role1"]},
            "Action": "sts:AssumeRole",
        }
    ],
}

policy_with_removed_sid = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Condition": {},
            "Effect": "Allow",
            "Principal": {"AWS": ["arn:aws:iam:::user/test-role1"]},
            "Action": "sts:AssumeRole",
        }
    ],
}

policy_with_updated_arn = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Condition": {},
            "Principal": {
                "AWS": [
                    "arn:aws:iam:::user/test-role1",
                    "arn:aws:iam:::user/test-role2",
                ]
            },
            "Action": "sts:AssumeRole",
        }
    ],
}

policy_with_removed_arn = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Condition": {},
            "Principal": {"AWS": ["arn:aws:iam:::user/test-role1"]},
            "Action": "sts:AssumeRole",
        }
    ],
}

policy_with_condition = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Condition": {"StringEquals": {"sts:ExternalId": "123456"}},
            "Effect": "Allow",
            "Principal": {"AWS": ["arn:aws:iam:::user/test-role1"]},
            "Action": "sts:AssumeRole",
        }
    ],
}


policy_with_empty_condition = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Condition": {},
            "Effect": "Allow",
            "Principal": {"AWS": ["arn:aws:iam:::user/test-role1"]},
            "Action": "sts:AssumeRole",
        }
    ],
}


@pytest.fixture
def iam_role():
    import json
    import boto3  # type: ignore

    role = "test-123"
    iam = boto3.client("iam")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(initial_policy))
    yield role


def test_get_arpd(iam_role):
    assert arpd_update.get_arpd(role_name=iam_role) == initial_policy


def test_add_external_id(iam_role):
    assert (
        arpd_update.add_external_id(
            external_id="123456", role_name=iam_role, dir_path=None
        )
        == policy_with_condition
    )


def test_remove_external_id(iam_role):
    assert (
        arpd_update.remove_external_id(role_name=iam_role, dir_path=None)
        == policy_with_empty_condition
    )


def test_add_sid(iam_role):
    assert (
        arpd_update.add_sid(role_name=iam_role, sid="1", dir_path=None)
        == policy_with_added_sid
    )


def test_remove_sid(iam_role):
    assert (
        arpd_update.remove_sid(role_name=iam_role, dir_path=None)
        == policy_with_removed_sid
    )


def test_update_arn(iam_role):
    assert (
        arpd_update.update_arn(
            role_name=iam_role,
            arn_list=["arn:aws:iam:::user/test-role2"],
            dir_path=None,
        )
        == policy_with_updated_arn
    )


def test_remove_arn(iam_role):
    assert (
        arpd_update.remove_arn(
            role_name=iam_role,
            arn_list=["arn:aws:iam:::user/test-role2"],
            dir_path=None,
        )
        == policy_with_removed_arn
    )
