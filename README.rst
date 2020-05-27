PyDiscover
==========

*PyDiscover: Simple Secure and Lightweight Python Service Discovery*

:Codename: ZaRZaner0
:Version: 1.0
:Code: https://github.com/cr0hn/pydiscover
:Issues: https://github.com/cr0hn/pydiscover/issues/
:Python version: Python 3.4 and above
:Author: Daniel Garcia (cr0hn) - @ggdaniel

Support this project
--------------------

Support this project (to solve issues, new features...) by applying the Github "Sponsor" button.

What's PyDiscover
-----------------

PyDiscover is a simple service discovery client and server, designed with simplicity, performance and security in mind. Instead of implement SSDP protocol or any else, use a very simple mechanism: send to the clients information as a JSON format.

PyDiscover is very flexible and lightweight, and incorporates a cypher mechanism to secure (password based) the communication between server and clients.

Features
--------

- Simple usage.
- Configurable multicast service discovery.
- Password protected access to server info (optional).
- AES encryption (if you defines a password).
- Custom channel definition.
- High server performance, based in the new Python asyncio module.
- Server can spread any information to clients. This information are sent/received as a JSON format.
- Simple configuration file

Install
-------

Install is so easy:

.. code-block:: bash

    # python3.4 -m pip install pydiscover

How it works?
-------------

**Architecture**:

PyDiscover is composed by client and server:

- Server listen for multicast clients request in the port 50000 (by default).
- Clients send requests using a multicast address to the port 50000.

**Virtual Channels (or magic)**:

Client and server must transmit information in the same *virtual channel (or magic)*. The magic is a pre-shared word that server/client known. Only messages with this word will be attended, performing the "virtual channel".

**Hidden mode**:

By default (per security reasons) server runs as **hidden mode**. This is: if server receives a messages without the correct magic or with wrong password, doesn't answer nothing to the client request. If we want that server answer with error message, we'll activate explicitly.

**Securing communication**

We can set a password for the server. When it's set, the information will be sent cyphered using AES to the clients. Only in the clients known the password could be understand the messages.

**Sent/received information**

Server must be started with *-d* param. This param referees to a *.cfg* file. This file must have the format:

.. code-block:: ini

    [DEFAULT]
    services = 10.0.0.1
    net_password = asfi0j9ask123

- A *[DEFAULT]* section.
- Any information as: *key = value*.

The DEFAULT section content will be sent as a JSON format to the clients.

Usage
-----

**Server**

Starting server in port 40000, with a password an the virtual channel is build by word: "askskAls828":

.. code-block:: bash

    # pydiscover-server -p 40000 --password 1238d8KKls_jj -m askskAls828 -d example.cfg

Disablind hidden mode:

.. code-block:: bash

    # pydiscover-server -p 40000 --password 1238d8KKls_jj -m askskAls828 -d example.cfg --disable-hidden

You can see more examples typing:

.. code-block:: bash

    # pydiscover-server -h

**Client**

Connecting to the server with the above configuration:

.. code-block:: bash

    # pydiscover-client -p 40000 --password 1238d8KKls_jj -m askskAls828 -v

Real example
------------

.. image:: https://raw.githubusercontent.com/cr0hn/pydiscover/master/pydiscover/example.jpg

What's new?
-----------

Version 1.0.0
+++++++++++++

- First version released

License
-------

PyDiscover is released under BSD licence.
