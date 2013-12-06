Soledad Scripts
===============

The scripts in this directory are meant to be used for development purposes.

Currently, the scripts are:

  * server-side-db.py: Gives access to server-side soledad user database,
    based on the configuration in /etc/leap/soledad-server.conf. One should
    use it as:

      python -i server-side-db.py <uuid>

  * client-side-db.py: Gives access to client-side soledad user database,
    based on data stored in ~/.config/leap/soledad. One should use it as:

      python -i client-side-db.py <uuid> <passphrase>
