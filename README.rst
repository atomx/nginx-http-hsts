
==================================
nginx HSTS module
==================================

The `ngx_http_hsts` module provides support for HTTP Strict Transport Security in nginx.


Dependencies
============
* Sources for nginx 1.x.x, and its dependencies.


Building
========

1. Unpack the nginx\_ sources::

    $ tar zxvf nginx-1.x.x.tar.gz

2. Unzip the sources for the digest module::

    $ unzip master.zip

3. Change to the directory which contains the nginx\_ sources, run the
   configuration script with the desired options and be sure to put an
   ``--add-module`` flag pointing to the directory which contains the source
   of the digest module::

    $ cd nginx-1.x.x
    $ ./configure --add-module=../nginx-http-hsts-master  [other configure options]

4. Build and install the software::

    $ make && sudo make install

5. Configure nginx using the module's configuration directives_.


Example
=======

You can enable HSTS by adding the following lines into
a ``main``, ``server`` or ``location`` section in your nginx configuration file::

  hsts  "2016-01-29" includeSubdomains;

Directives
==========

hsts
~~~~
:Syntax:  ``hsts`` "``YYYY-MM-DD``" | ``off`` [``includeSubdomains``] [``preload``]
:Default: ``off``
:Context: main, server, location
:Description:
  Enable or disable HSTS. The date is until when the browser shall access the server 
  in a secure-only fashion. It is suggested to put this the day before your certificate expires.
 
  The optional ``includeSubdomains`` specifies all subdomains should be HTTPS as well.

  For the optional ``preload`` token see: https://hstspreload.appspot.com/
  

Testing
==========
::

    $ cd test
    $ NGINX=/home/erik/nginx-1.9.1/objs/nginx ./test.sh

