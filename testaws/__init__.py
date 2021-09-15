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
    Accept string (str).
    Return the string with the first character in upper case.
    (For example, "disableApiTermination" returns "DisableApiTermination"
    """
    capital = string[0].upper()
    return capital + string[1:]


def match_env_type_num_name_scheme(objects, infix, env=r"^[^-]+-", num=r"-[0-9][0-9]$"):
    """
    Accept objects (iterable of aws objects with Tags key),
    infix (raw string for use as regex),
    optional env and num (raw strings for use as regex:
    default to r"^[^-]+-" and r"-[0-9][0-9]$").
    Return objects with a Name tag matching the regex
    env-infix-num.
    Example: prod-web-01
    """
    regex = re.compile(env + infix + num)
    return objects_tags_key_values_matches_regex(objects, "Name", regex)


@lru_cache(maxsize=128)
def ask_terraform(query):
    """
    Accept a freeform terraform query.
    Return terraform's answer.
    """
    tf_console = ["terraform", "console"]
    tf = subprocess.run(
        tf_console, input=query, stdout=subprocess.PIPE, encoding="utf-8"
    )
    return tf.stdout.strip().strip('"')

def terraform_output(query):
    """
    Accept a terraform output query.
    Return terraform's answer.
    """
    tf_output = ["terraform", "output", query]
    tf = subprocess.run(
        tf_output, stdout=subprocess.PIPE, encoding="utf-8"
    )
    return tf.stdout.strip().strip('"')

def terraform_value(what_type, name):
    query = f"{what_type}.{name}"
    return ask_terraform(query)

def terraform_data(data):
    """
    Accept data (name of a terraform data object).
    Return terraform's value for that data object.
    """
    return terraform_value('data', data)


def terraform_variable(var):
    """
    Accept var (name of a terraform variable).
    Return terraform's value for that variable.
    """
    return terraform_value('var', var)


def terraform_struct(query):
    """
    Accept a terraform query.
    Return terraform's value for that variable as a data structure.
    (list or dict, as appropriate)

    """
    return yaml.safe_load(ask_terraform(query))


def get_security_groups(filters=[]):
    return ec2_client.describe_security_groups(Filters=filters)["SecurityGroups"]


def get_load_balancers():
    return elbv2_client.describe_load_balancers()["LoadBalancers"]


def get_instances(filters=[]):
    reservations = ec2_client.describe_instances(Filters=filters)["Reservations"]
    return list(chain.from_iterable(r["Instances"] for r in reservations))


def get_addresses(filters=[]):
    return ec2_client.describe_addresses(Filters=filters)["Addresses"]

def get_s3_buckets_names():
    return [
        bucket['Name']
        for bucket in s3_client.list_buckets()['Buckets']
    ]

def objects_tags_key_values_matches_regex(objects, key, regex):
    return [
        obj
        for obj in objects
        if tags_key_value_matches_regex(obj, key, regex)
    ]


def tags_key_value_matches_regex(aws_object, key, regex):
    tags = aws_object["Tags"]
    return any(
        tag
        for tag in tags
        if tag["Key"] == key and regex.match(tag["Value"])
    )


def instances_security_groups_ids(instances):
    """
    Accept instances (list of instance objects).
    Return all security group ids for those instances
    as a set.
    """
    return set(
        group["GroupId"] for group in instances_security_groups(instances)
    )


def instances_security_groups(instances):
    """
    Accept instances (list of instance objects).
    Return all security groups for those instances,
    as a list of dicts with keys GroupId and GroupName.
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
    Accept group_ids (list).
    Return all ingress rules for those groups as a list.
    """
    groups = [ec2.SecurityGroup(gid) for gid in group_ids]
    return [rule for group in groups for rule in group.ip_permissions]


def security_groups_egress(group_ids):
    """
    Accept group_ids (list).
    Return all egress rules for those groups as a list.
    """
    groups = [ec2.SecurityGroup(gid) for gid in group_ids]
    return [
        rule
        for group in groups
        for rule in group.ip_permissions_egress
    ]


def rules_ports(rules):
    """
    Accept rules (list).
    Return set of ports covered by those rules.
    """
    return set(
        port
        for rule in rules
        for port in range(rule["FromPort"], rule["ToPort"] + 1)
    )


def port_in_rule(port, rule):
    """
    Accept port (int) and rule.
    Return True if port is covered by the rule.
    Return False otherwise.
    """
    try:
        return port in range(rule["FromPort"], rule["ToPort"] + 1)
    except KeyError:
        return False


def instances_ingress_rules(instances):
    """
    Accept instances (list)
    Return ingress rules
    """
    sg_ids = instances_security_groups_ids(instances)
    return security_groups_ingress(sg_ids)


def instances_egress_rules(instances):
    """
    Accept instances (list)
    Return egress rules
    """
    sg_ids = instances_security_groups_ids(instances)
    return security_groups_egress(sg_ids)


def instances_ingress_ports(instances):
    """
    Accept instances (list)
    Return set of ingress ports
    """
    rules = instances_ingress_rules(instances)
    return rules_ports(rules)


def instances_egress_ports(instances):
    """
    Accept instances (list)
    Return set of egress ports
    """
    rules = instances_egress_rules(instances)
    return rules_ports(rules)


def instances_egress_rules_for_port(instances, port):
    """
    Accept instances (list) and port (int).
    Return egress rules which include port
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
    Accept instances (list) and port (int).
    Return ingress rules which include port
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
    Accept rules (list).
    Retrun dict with keys 'cidrs' and 'sgids'
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
    Accept instances (list) and port (int).
    Return dict with keys 'cidrs' and 'sgids' of sources that can reach port
    on instances.
    """
    rules = instances_ingress_rules_for_port(instances, port)
    return rules_cidrs_and_security_groups(rules)


def instances_attribute(instances, attribute):
    """
    Accept instances (list) and attribute (str).
    Return list that attributes value for the instances.
    See
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.ec2_client.describe_instance_attribute
    for usable attributes.
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
    ids = [instance['InstanceId'] for instance in instances]
    return ec2_client.describe_addresses(
        Filters=[{
            'Name': 'instance-id',
            'Values': ids,
        }]
    )['Addresses']


def buckets_encrypted(buckets):
    """
    Accept a list of aws bucket names
    Return bucket's encryption object or None for each bucket.
    """

    def maybe_encrypted(bucket):
        try:
            return s3_client.get_bucket_encryption(Bucket=bucket)[
                "ServerSideEncryptionConfiguration"
            ]
        except BotoClientError:
            return None

    return [maybe_encrypted(bucket) for bucket in buckets]
