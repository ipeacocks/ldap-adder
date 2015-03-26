This program is for quick adding new employee to openLDAP server and creating Redmine account with the same credentials (better of course if your Redmine can work with LDAP directly).

In the end new employee can receive email notification with new password.

LDAP Adder Tool looks as follow:

![Output sample](https://github.com/ipeacocks/ldap_adder_tool/raw/master/demo.gif)

For Linux I use "Calm" theme of Tkinter:

![Output sample](https://github.com/ipeacocks/ldap_adder_tool/raw/master/demo-linux.gif)

Before program launch you need to have some python libs. Read about that in requirements.txt. Use next command to install all packs at once:

```bash
# pip install -r requirements.txt
```

And maybe setup before few packs from standard linux repos:

```bash
# sudo apt-get install -y python-dev libldap2-dev libsasl2-dev libssl-dev
```

Program works in all OSes. Wrote on Python 2 and Tkinter lib. 

I've used these libraries :

http://python-redmine.readthedocs.org/

http://www.python-ldap.org/
