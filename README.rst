test-aws
========

Helper functions for writing pytest against AWS infrastructure.

While it need not be used with terraform,
it includes terraform helpers to look up variables, data sources, and other
terraform objects.

`test-aws` has been in use for a few years now,
but you should not consider it stable (yet).
Pin your version in your `requirements.txt`,
please, or be prepared to rewrite some of your tests on occasion.

usage
~~~~~

Create a `test` directory in your root terraform module.

In `test/conftest.py`, place:

.. code-block:: python

    import testaws as t

    @pytest.fixture(scope="session")
    def my_vpc_instances():
        filters = tuple([{"Name": "vpc-id", "Values": ["vpc-0123456789abcdef0"]}])
        return t.get_instances(filters)

    @pytest.fixture(scope="session")
    def my_offices():
        return {
            t.terraform_variable("cidr.new_york"),
            t.terraform_variable("cidr.buenos_aires"),
            t.terraform_variable("cidr.paris"),
            t.terraform_variable("cidr.cairo"),
            t.terraform_variable("cidr.djakarta"),
            t.terraform_variable("cidr.adelaide"),
        }

    @pytest.fixture(scope="session")
    def developers():
        return {
            t.terraform_variable("cidr.san_francisco"),
            t.terraform_variable("cidr.mumbai"),
        }


Most objects are going to be `sets`.

Write some tests for a your web instances in `test/test_web.py`:

.. code-block:: python

    import pytest

    import testaws as t


    @pytest.fixture(scope="module", name="web")
    def web_instances(my_vpc_instances):
        # prod-web-03 stage-web-01 test-web-01
        return t.match_3_part_name_schema(my_vpc_instances, r"web")

    def test_has_public_ip(web):
        public_ips = [instance.get('PublicIpAddress') for instance in web]
        assert all(public_ips)

    def test_has_elastic_ip(web):
        eips = t.instances_elastic_ips(web)
        assert all(eips)

    def test_accept_only_ssh_and_web(web):
        actual = tests.instances_ingress_ports(web)
        assert actual == {22, 443}

    def test_accepts_ssh_from_devs_only(web, developers):
        actual = t.instances_port_ingress_sources(web, port=443)
        assert actual["cidrs"] == developers
        assert actual["sgids"] == set()

    def test_accepts_web_from_offices_only(web, my_offices):
        actual = t.instances_port_ingress_sources(web, port=443)
        assert actual["cidrs"] == my_offices
        assert actual["sgids"] == set()

    def test_send_only_web(web):
        actual = tests.instances_egress_ports(web)
        assert actual == {443}

    def test_has_api_termination_disabled(web):
        disabled = t.instances_attribute(web, 'disableApiTermination')
        assert disabled
        assert all(disabled)


Write some tests for all of your instances in `test/test_all.py`:

.. code-block:: python

    import pytest

    import testaws as t

    def test_none_accept_ssh_from_world(my_vpc_instances):
        ssh_ingress_rules = t.instances_ingress_rules_for_port(my_vpc_instances, 22)
        actual = t.rules_cidrs_and_security_groups(ssh_ingress_rules)
        assert "0.0.0.0/0" not in actual["cidrs"]


Run `pytest`.

philosophy and alternatives
---------------------------

The philosophy of `test-aws` is:

* test deployed resources, not the deploy code.
* make broad assertions about the state of your infrastructure - for instance:
  - nothing has 22 open from the world.
  - web instances only allow 443 in.
* test in production.
  - It's not that we are *not* going to test before we go to prod.
  - It is that we are going to *continue* testing once we reach prod.
* use existing testing tools (in this case pytest and Python)
  rather than having new tools specific to Infrastructure-as-Code.
* this tool is only one of many for testing Infrastructure-as-Code.


Some other tools you might consider are:

* https://terratest.gruntwork.io/

* https://github.com/newcontext-oss/kitchen-terraform

* https://community.chef.io/tools/chef-inspec

* https://serverspec.org/
