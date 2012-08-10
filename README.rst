========================
Contributed Bro Scripts
========================

This is an unofficial collection of Bro scripts that have been contributed by the Bro community. Scripts that have been included here have been reviewed and approved. Please note that the review is only for security issues, and not for syntax, logic, or performance.

This file only contains a short summary about each script. Each script is accompanied by important documentation, that should be carefully read before attempting to use the script. This documentation is located in the script file itself, as a comment at the top of the file.

To contribute to this repository, fork this repo, and submit a pull request.

Script List:
-----------

``conn-add-geodata.bro``
    Adds countries for the originator and responder of a connection to the connection logs.

``http-exe-bad-attributes.bro``
    Detects bad executable downloaded by watching for attributes of the connection or request.    

``roam.bro`` 
    Collects IP-to-MAC mappings of machines that may have more than one IP address over time due to a DHCP server on the network.

``sidejack.bro`` 
    Detects the reuse of session cookies in different contexts.

``scan.bro`` 
    The Bro 1.5 scan detector ported to Bro 2.0. For using this in a cluster, see ``scan.cluster.bro``.
