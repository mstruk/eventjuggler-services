Eventjuggler Services
=====================


Prerequisites
=============

- Java Development Kit 7
- Recent Git client
- Recent Maven 3
- WildFly 8.0.0.Alpha1


Installation
============

To build and install to a running WildFly instance run:

    mvn clean install jboss-as:deploy


Distribution
============

The dist component downloads and extracts WildFly 8.0.0.Alpha1. Then it installs EventJuggler Services into the WildFly installation.

To build with WildFly run:

    mvn clean install -Prelease

Then start with:

    dist/target/ejs-<PROJECT VERSION>/bin/standalone.sh

Note: documentation is available in dist/target - to set the URL for the SaaS installation of EJS use "-Dejs.saas.url=<base url>" when building the distribution


Testsuite
=========

The testsuite contains a set of integration tests. The tests can be execute in either managed or remote mode. In managed mode the
tests have been configured to use the WildFly installation created by the build module.

To run the testsuite in managed mode, run:

    mvn -Prelease -Pit-managed clean install

To run the testsuite in remote mode, first start WildFly with EventJuggler Services and PicketLink subsystem installed, and run:

    mvn -Pit-remote clean install
