from functools import lru_cache
from itertools import chain
import os
import re
import subprocess

import boto3
from botocore.exceptions import ClientError as BotoClientError
from botocore.exceptions import NoRegionError as BotoNoRegionError
import pytest
import yaml

from testaws import __about__

try:
    ec2_client = boto3.client("ec2")
    s3_client = boto3.client("s3")
    ec2 = boto3.resource("ec2")
    elbv2_client = boto3.client("elbv2")
except BotoNoRegionError:
    pass


def uppercase_initial(string):
    """
    Return a capitalized string.
    
    :param string: Input string
    :type string: str
    :return: Capitalized input string
    :rtype: str

    >>> uppercase_initial("disableApiTermination")
    "DisableApiTermination"
    """
    capital = string[0].upper()
    return capital + string[1:]


def match_env_type_num_name_scheme(objects, infix, env=r"^[^-]+-", num=r"-[0-9][0-9]$"):
    """
    Return objects with a Name tag matching the regex
    (env)(infix)(num)

    Example: prod-web-01

    This wraps objects_tags_key_values_matches_regex.

    :param objects: Iterable of aws objects with a Tags key
    :type objects: iterable
    :param infix: Raw string for use as regex
    :type objects: str
    :param env: Raw string for use as regex.
        Defaults to r"^[^-]+-" 
    :type env: str, optional
    :param num: Raw string for use as regex.
        defaults to r"-[0-9][0-9]$").
    :type num: str, optional
    :return: List of returned boto3 objects
    :rtype: list
    """
    regex = re.compile(env + infix + num)
    return objects_tags_key_values_matches_regex(objects, "Name", regex)


def objects_tags_key_values_matches_regex(objects, key, regex):
    """
    Return objects with tagged with key matching regex.
    You may wish to use match_env_type_num_name_scheme instead when possible.

    :param objects: Iterable of aws objects with a Tags key
    :type objects: iterable
    :param key: Tag to compare against
    :type key: str
    :param regex: Regex to match
    :type regex: re
    :return: List of returned boto3 objects
    :rtype: list
    """
    return [
        obj
        for obj in objects
        if tags_key_value_matches_regex(obj, key, regex)
    ]


def tags_key_value_matches_regex(aws_object, key, regex):
    """
    Return true if aws_object's key key matches regex, 
    otherwise False.

    :param aws_object: A boto3 aws object to check
    :param key: Tag to compare against
    :type key: str
    :param regex: Regex to match
    :type regex: re
    :return: True or False, if there was a match
    :rtype: bool
    """
    tags = aws_object["Tags"]
    return any(
        tag
        for tag in tags
        if tag["Key"] == key and regex.match(tag["Value"])
    )


@lru_cache(maxsize=128)
def ask_terraform(query):
    """
    Ask terraform console a question.
    When possible,
    it is easier to use terraform_data or terraform_variable instead.
    Use terraform_struct instead if the output will be used as a data structure.

    :param query: terraform console expression
    :type query: str
    :return: Terraform's output
    :rtype: str
    """
    tf_console = ["terraform", "console"]
    tf = subprocess.run(
        tf_console, input=query, stdout=subprocess.PIPE, encoding="utf-8"
    )
    return tf.stdout.strip().strip('"')

def terraform_output(query):
    """
    Ask terraform output a question.

    :param query: terraform output key
    :type query: str
    :return: Terraform's output
    :rtype: str
    """
    tf_output = ["terraform", "output", query]
    tf = subprocess.run(
        tf_output, stdout=subprocess.PIPE, encoding="utf-8"
    )
    return tf.stdout.strip().strip('"')

def terraform_value(what_type, name):
    """
    Ask terraform console for a data or a variable value.
    When possible,
    it is easier to use terraform_data or terraform_variable instead.

    :param what_type: "data" or "var"
    :type what_type: str
    :param name: Name of data or var to return
    :type name: str
    :return: Terraform's output
    :rtype: str
    """
    if what_type not in ['data', 'var']:
        raise ValueError
    query = f"{what_type}.{name}"
    return ask_terraform(query)

def terraform_data(data):
    """
    Ask terraform console for a data value.

    :param data: terraform data to look up
    :type data: str
    :return: Terraform's output
    :rtype: str
    """
    return terraform_value('data', data)


def terraform_variable(var):
    """
    Ask terraform console for a variable value.

    :param var: terraform var to look up
    :type var: str
    :return: Terraform's output
    :rtype: str
    """
    return terraform_value('var', var)


def terraform_struct(query):
    """
    Ask terraform console a question,
    returning the answer as a data structure
    (list or dict, as appropriate)

    :param query: terraform console expression
    :type query: str
    :return: Terraform's output
    :rtype: list or dict
    """
    return yaml.safe_load(ask_terraform(query))


def get_security_groups(filters=[]):
    """
    Return security groups matching filter.
    See 
    https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
    and 
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
    for details on available filters.

    :param filters: Filters to apply.
        For example: filters = [{"Name": "vpc-id", "Values": ["vpc-0123456789abcdef0"]}]
    :type filters: list of dicts, optional.
    :return: set of security groups
    :rtype: set
    """
    return ec2_client.describe_security_groups(Filters=filters)["SecurityGroups"]


def get_load_balancers():
    """
    Return all load balancers.

    :return: List of load balancers.
    :rtype: list
    """
    return elbv2_client.describe_load_balancers()["LoadBalancers"]


def get_instances(filters=[]):
    """
    Return instances matching filter.

    :param filters: Filters to apply.
    :type filters: list of dicts, optional.
    :return: list of instances
    :rtype: list
    """
    reservations = ec2_client.describe_instances(Filters=filters)["Reservations"]
    return list(chain.from_iterable(r["Instances"] for r in reservations))


def get_addresses(filters=[]):
    """
    Return addresss matching filter.

    :param filters: Filters to apply.
    :type filters: list of dicts, optional.
    :return: list of addresss
    :rtype: list
    """
    return ec2_client.describe_addresses(Filters=filters)["Addresses"]

def get_s3_buckets_names():
    """
    Return all S3 bucket names.

    :return: List of S3 bucket names.
    :rtype: list
    """
    return [
        bucket['Name']
        for bucket in s3_client.list_buckets()['Buckets']
    ]

def instances_security_groups_ids(instances):
    """
    Return the set of security group IDs applied to instances.

    :param instances: list of ec2 instance objects
    :type instances: list
    :return: set of security group IDs applied to instances
    :rtype: set
    """
    return set(
        group["GroupId"] for group in instances_security_groups(instances)
    )


def instances_security_groups(instances):
    """
    Return security groups associated with instances.

    :param instances: list of ec2 instance objects
    :type instances: list
    :return: list of dicts with keys GroupId and GroupName
    :rtype: list
    """
    # we turn the groups into frozensets to make them hashable,
    # so we can use set to deduplicate.
    # On the way out, we turn them back into dicts.
    unique = set(
        frozenset(group.items())
        for instance in instances
        for group in instance["SecurityGroups"]
    )
    return [dict(group) for group in unique]


def security_groups_ingress(group_ids):
    """
    Return all ingress rules for a list of security group IDs

    :param group_ids: list of security group IDs
    :type group_ids: list
    :return: list of security group ingress rules
    :rtype: list
    """
    groups = [ec2.SecurityGroup(gid) for gid in group_ids]
    return [rule for group in groups for rule in group.ip_permissions]


def security_groups_egress(group_ids):
    """
    Return all egress rules for a list of security group IDs

    :param group_ids: list of security group IDs
    :type group_ids: list
    :return: list of security group egress rules
    :rtype: list
    """
    groups = [ec2.SecurityGroup(gid) for gid in group_ids]
    return [
        rule
        for group in groups
        for rule in group.ip_permissions_egress
    ]


def rules_ports(rules):
    """
    Return set of ports covered by a list of security group rules.

    :param rules: list of security group rules
    :type rules: list
    :return: set of ports
    :rtype: set
    """
    return set(
        port
        for rule in rules
        for port in range(rule["FromPort"], rule["ToPort"] + 1)
    )


def port_in_rule(port, rule):
    """
    Return True or False if port is covered by a security group rule.

    :param port: port to check
    :type port: int
    :param rule: security group rule to check
    :return: True or False if port is covered by a security group rule.
    :rtype: bool
    """
    try:
        return port in range(rule["FromPort"], rule["ToPort"] + 1)
    except KeyError:
        return False


def instances_ingress_rules(instances):
    """
    Return all ingress rules for a list of instances.

    :param instances: list of instances
    :type instances: list
    :return: list of security group ingress rules
    :rtype: list
    """
    sg_ids = instances_security_groups_ids(instances)
    return security_groups_ingress(sg_ids)


def instances_egress_rules(instances):
    """
    Return all egress rules for a list of instances.

    :param instances: list of instances
    :type instances: list
    :return: list of security group egress rules
    :rtype: list
    """
    sg_ids = instances_security_groups_ids(instances)
    return security_groups_egress(sg_ids)


def instances_ingress_ports(instances):
    """
    Return all allowed ingress ports for a list of instances.

    :param instances: list of instances
    :type instances: list
    :return: set of allowed ingress ports
    :rtype: set
    """
    rules = instances_ingress_rules(instances)
    return rules_ports(rules)


def instances_egress_ports(instances):
    """
    Return all allowed egress ports for a list of instances.

    :param instances: list of instances
    :type instances: list
    :return: set of allowed egress ports
    :rtype: set
    """
    rules = instances_egress_rules(instances)
    return rules_ports(rules)


def instances_egress_rules_for_port(instances, port):
    """
    Return egress rules applied to instances which include port.

    :param instances: list of instances
    :type instances: list
    :param port: port
    :type port: int
    :return: list of egress rules
    :rtype: list
    """
    sg_ids = instances_security_groups_ids(instances)
    rules = security_groups_egress(sg_ids)
    return [
        rule
        for rule in rules
        if port_in_rule(port, rule)
    ]


def instances_ingress_rules_for_port(instances, port):
    """
    Return ingress rules applied to instances which include port.

    :param instances: list of instances
    :type instances: list
    :param port: port
    :type port: int
    :return: list of ingress rules
    :rtype: list
    """
    sg_ids = instances_security_groups_ids(instances)
    rules = security_groups_ingress(sg_ids)
    return [
        rule
        for rule in rules
        if port_in_rule(port, rule)
    ]


def rules_cidrs_and_security_groups(rules):
    """
    Return a dict with keys "cidrs" and "sgids" 
    from a list of security group rules.

    :param rules: list of security group rules
    :type rules: list
    :return: Dict with keys "cidrs" and "sgids"
    :rtype: dict
    """
    cidrs = set(
        ip_range["CidrIp"]
        for rule in rules
        for ip_range in rule["IpRanges"]
    )
    sgids = set(
        group_pair["GroupId"]
        for rule in rules
        for group_pair in rule["UserIdGroupPairs"]
    )
    return {"cidrs": cidrs, "sgids": sgids}


def instances_port_ingress_sources(instances, port):
    """
    Return dict with keys 'cidrs' and 'sgids'
    of sources that can reach port on instances.

    :param instances: list of instances
    :type instances: list
    :param port: port
    :type port: int
    :return: Dict with keys "cidrs" and "sgids", of network sources
    :rtype: dict
    """
    rules = instances_ingress_rules_for_port(instances, port)
    return rules_cidrs_and_security_groups(rules)


def instances_attribute(instances, attribute):
    """
    Return a list of the indicated attribute values for instances.

    See
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.ec2_client.describe_instance_attribute
    for usable attributes.

    :param instances: list of instances
    :type instances: list
    :param attributes: attribute to look up
    :type attributes: str
    :return: list of attribute values
    :rtype: list
    """
    capitalized_attribute = uppercase_initial(attribute)

    return [
        ec2_client.describe_instance_attribute(
            Attribute=attribute,
            InstanceId=instance['InstanceId']
        )[capitalized_attribute]['Value']
        for instance in instances
    ]


def instances_elastic_ips(instances):
    """
    Return a list of elastic IPs associated with instances.

    :param instances: list of instances
    :type instances: list
    :return: list of elastic IPs.
    :rtype: list
    """

    ids = [instance['InstanceId'] for instance in instances]
    return ec2_client.describe_addresses(
        Filters=[{
            'Name': 'instance-id',
            'Values': ids,
        }]
    )['Addresses']


def buckets_encrypted(buckets):
    """
    Return bucket's encryption object or None for each bucket.

    :param buckets: list of buckets
    :type buckets: list
    :return: list of encryption object / None
    :rtype: list
    """

    def maybe_encrypted(bucket):
        try:
            return s3_client.get_bucket_encryption(Bucket=bucket)[
                "ServerSideEncryptionConfiguration"
            ]
        except BotoClientError:
            return None

    return [maybe_encrypted(bucket) for bucket in buckets]
