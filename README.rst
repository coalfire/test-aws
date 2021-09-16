test-aws
========

Helper functions for writing pytest against AWS infrastructure.

``test-aws`` includes terraform helpers to look up 
variables, data sources, and other terraform objects.

``test-aws`` has been in use for a few years now,
but you should not consider it stable (yet).
Pin your version in your ``requirements.txt``,
please, or be prepared to rewrite some of your tests on occasion.

Complete documentation is at
https://testaws.readthedocs.io/en/latest/index.html.

usage
~~~~~

Create a ``test`` directory.

In ``test/conftest.py``, place:

.. code-block:: python

    import testaws as t

    @pytest.fixture(scope="session")
    def my_vpc_instances():
        filters = tuple([{"Name": "vpc-id", "Values": ["vpc-0123456789abcdef0"]}])
        return t.get_instances(filters)

Write some tests for all of your instances in ``test/test_all.py``:

.. code-block:: python

    import pytest

    import testaws as t

    def test_none_accept_ssh_from_world(my_vpc_instances):
        ssh_ingress_rules = t.instances_ingress_rules_for_port(my_vpc_instances, 22)
        actual = t.rules_cidrs_and_security_groups(ssh_ingress_rules)
        assert "0.0.0.0/0" not in actual["cidrs"]


Run ``pytest``.

Perhaps you would like to test that your internally reachable web instances
are only reachable from your offices,
and that they can only be ssh'ed to from your developer offices.

If you have terraform like this:

.. code-block:: terraform

    variable "cidr" {
      default = {
        cidr.adelaide      = "10.10.0.0/24"
        cidr.buenos_aires  = "10.10.0.0/24"
        cidr.cairo         = "10.10.0.0/24"
        cidr.djakarta      = "10.10.0.0/24"
        cidr.new_york      = "10.10.0.0/24"
        cidr.paris         = "10.10.0.0/24"

        cidr.mumbai        = "10.10.0.0/24"
        cidr.san_francisco = "10.10.0.0/24"
      }
    }


then you can place this is your ``test/conftest.py``:

.. code-block:: python

    @pytest.fixture(scope="session")
    def my_offices():
        return {
            t.terraform_variable("cidr.adelaide"),
            t.terraform_variable("cidr.buenos_aires"),
            t.terraform_variable("cidr.cairo"),
            t.terraform_variable("cidr.djakarta"),
            t.terraform_variable("cidr.new_york"),
            t.terraform_variable("cidr.paris"),
        }

    @pytest.fixture(scope="session")
    def developers():
        return {
            t.terraform_variable("cidr.mumbai"),
            t.terraform_variable("cidr.san_francisco"),
        }


and write tests for your web instances in ``tests/test_web.py``:

.. code-block:: python

    import pytest

    import testaws as t


    @pytest.fixture(scope="module", name="web")
    def web_instances(my_vpc_instances):
        # prod-web-03 stage-web-01 test-web-01
        return t.match_env_type_num_name_scheme(my_vpc_instances, r"web")

    def test_has_public_ip(web):
        public_ips = [instance.get('PublicIpAddress') for instance in web]
        assert all(public_ips)

    def test_has_elastic_ip(web):
        eips = t.instances_elastic_ips(web)
        assert all(eips)

    def test_accepts_only_ssh_and_web(web):
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

    def test_sends_only_web(web):
        actual = tests.instances_egress_ports(web)
        assert actual == {443}

    def test_is_type_t3_medium(web):
        instance_types = [instance.get('InstanceType') for instance in web]
        assert all(i_type == "t3.medium" for i_type in instance_types)

    def test_has_api_termination_disabled(web):
        disabled = t.instances_attribute(web, 'disableApiTermination')
        assert disabled
        assert all(disabled)


philosophy and alternatives
---------------------------

``test-aws`` has some guiding principals:

* test deployed resources, not the deploy code.
* make broad assertions about the state of your infrastructure - for instance:

   * nothing has 22 open from the world.
   * web instances only allow 443 in.

* test in production.

   * It's not that we are *not* going to test before we go to prod.
   * It is that we are going to *continue* testing once we reach prod.

* use existing testing tools (in this case pytest and Python)
  rather than having new tools specific to Infrastructure-as-Code.
* ``test-aws`` is only one of many tools for testing Infrastructure-as-Code.
* we don't think other Infrastructure-as-Code philosphies are wrong,
  but these are what ``test-aws`` is trying to accomplish.


Some other tools you might consider are:

* https://terratest.gruntwork.io/

* https://github.com/newcontext-oss/kitchen-terraform

* https://community.chef.io/tools/chef-inspec

* https://serverspec.org/

development
------------

We need tests, 
and we need more docstrings.

Function names could do with a thorough review and setting a standard format.

.. code-block:: shell

    make help
