#!/usr/bin/python

import Tkinter as tk
import tkMessageBox
# themed tk
import ttk

# for random password generation
import random
import string

#for SHA-hash password generation
import sha
from base64 import b64encode

# for creating user in openLDAP
import ldap
import ldap.modlist as modlist
import ldif

from StringIO import StringIO

# for sending welcome emails
import smtplib

# for creating user through Redmine API
from redmine import Redmine
import warnings

# setting: addresses, servers and so on
# local file
import settings

import re


def label(root, row, column, text):
    L = ttk.Label(root, text=text, anchor='w',justify=tk.LEFT, width=16)
    L.grid(row=row,column=column,sticky="nw",padx=4, pady=1)
    return L


def button(root, row, column, text, command, columnspan=1, sticky="e"):
    B = ttk.Button(root, text=text, command=command, width=15)
    B.grid(row=row, column=column, sticky=sticky, padx=8, pady=8, columnspan=columnspan)


def entry(root, row, column, insert="", show="", width=32):
    E = ttk.Entry(root, width=width)
    E.insert(0, insert)
    E.config(show=show)
    E.grid(row=row,column=column, padx=4, pady=1)
    return E

def check_box(root, row, column, text, variable, columnspan=1):
    CB = ttk.Checkbutton(root, text=text, variable=variable)
    CB.grid(row=row, column=column, sticky="w", columnspan=columnspan, padx=4, pady=1)


def text_field_w_scroll(root, width, height, text, row, column, column_scroll, columnspan=1):
    text_field = tk.Text(root, width=width, height=height)
    text_field.insert(tk.END, text)
    text_field.grid(row=row, column=column, columnspan=columnspan)
    scroll = ttk.Scrollbar(root)
    scroll.config(command=text_field.yview)
    scroll.grid(row=row, column=column_scroll, sticky="nws")
    text_field.config(yscrollcommand=scroll.set)
    return text_field


def show_ldif():

    givenname = var0.get().strip()
    sn = var1.get().strip()
    country = var2.get().strip()
    location = var3.get().strip()
    accessible_host = var5.get().strip()
    organization = var6.get().strip()
    employeetype = var7.get()
    skype = var8.get().strip()
    phone = var9.get().strip()
    ssh_key = var10.get("1.0", tk.END).strip()
    # fixme: why new line in the end of text widget?
    ssh_key = ssh_key.strip()
    password = random_password(8)   
    uidnumber = var11.get().strip()

    """
    # main window
    Country - 2 letters
    POSIX UID - should be digit

    # result
    Send welcome mail
    """

    if not re.match("^[A-Za-z\s\-]{2,}$", givenname):
        tkMessageBox.showerror("Error", "First name is not correct!")
    elif not re.match("^[A-Za-z\-]{2,}$", sn):
        tkMessageBox.showerror("Error", "Second name is not correct!")
    elif not re.match("^[A-Z]{2}$", country):
        tkMessageBox.showerror("Error", "Country is not correct!\nShould be 2 capital letters.")
    elif not re.match("^\w{2,}$", location):
        tkMessageBox.showerror("Error", "City is not correct!")
    # can be IP or hostname
    elif not re.match("^[a-z0-9]{1,}\.[a-z]{2,}$|^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", accessible_host):
        tkMessageBox.showerror("Error", "Accessible Host is not correct!")
    elif organization == "":
        tkMessageBox.showerror("Error", "Organization is not correct!")
    elif skype == "":
        tkMessageBox.showerror("Error", "Skype can't be empty") 
    elif not re.match("^\+[0-9]{11,}$", phone):
        tkMessageBox.showerror("Error", "Phone is not correct!\nUse international format.") 
    elif ssh_key == "":
        tkMessageBox.showerror("Error", "SSH Key is not correct!") 
    elif not re.match("^[0-9]{4,}$", uidnumber):
        tkMessageBox.showerror("Error", "UID is not correct!\nUse digits only.") 
    else:
        cn = givenname[0].lower() + sn.lower()
        email = cn + '@' + settings.mail_domain
        password = random_password(8)
        ctx = sha.new(password) 
        hash = "{SHA}" + b64encode(ctx.digest())

        # ldif is import format for openLDAP
        ldif_list =[]
        ldif_list.append(("dn: cn=%s," % cn) + settings.ldap_employees_dn + "\n")
        ldif_list.append('c: %s\n'% country)
        ldif_list.append('cn: %s\n'% cn)
        ldif_list.append('employeetype: %s\n' % employeetype)
        ldif_list.append('gidnumber: 500\n')
        ldif_list.append('givenname: %s\n' % givenname)
        ldif_list.append('homedirectory: /home/%s\n' % cn)
        ldif_list.append('host: %s\n' % accessible_host)
        ldif_list.append('l: %s\n' % location)
        ldif_list.append('loginshell: /bin/bash\n')
        ldif_list.append('mail: %s\n' % email)
        ldif_list.append('o: %s\n' % organization)
        ldif_list.append(('objectclass: inetOrgPerson\n'
                          'objectclass: posixAccount\n'
                          'objectclass: top\n'
                          'objectclass: shadowAccount\n'
                          'objectclass: ldapPublicKey\n'
                          'objectclass: extensibleObject\n'))
        ldif_list.append('labeleduri: skype://%s\n' % skype)
        ldif_list.append('sn: %s\n' % sn)
        ldif_list.append('sshpublickey: %s\n' % ssh_key)
        #ldif_list.append('st: %s\n' % (address))
        ldif_list.append('telephonenumber: %s\n' % phone)
        ldif_list.append('uid: %s\n' % (cn))
        ldif_list.append('uidnumber: %s\n' % uidnumber)
        ldif_list.append('userpassword: %s' % hash)

        ldif = ''.join(ldif_list)

        top = tk.Toplevel(root)
        top.title("Result")
        top.resizable(0,0)
        top.focus_set()                                                        
        top.grab_set()

        top.tk.call('wm', 'iconphoto', top._w, logo)

        ldif_text = text_field_w_scroll(top, 55, 27, ldif, 0, 0, 2, 2)

        var13 = tk.IntVar()
        check_box(top, 2, 0, "Send welcome mail", var13)
        var14 = entry(top, 2, 1, "address", width=28)
        var15 = tk.IntVar()
        check_box(top, 1, 0, "Create Redmine account", var15, 2)
        label(top, 3, 0, '')


        # http://stackoverflow.com/questions/6920302/passing-argument-in-python-tkinter-button-command
        button(top, 4, 0, "Copy to Clipboard", lambda: copy_ldif(ldif_text), sticky="w")
        button(top, 4, 1, "Import", lambda: yes_no(ldif_text, var13, 
               var15, var14, skype, cn, givenname, sn, employeetype,
               organization, location, email, password), columnspan=2)


def copy_ldif(text_object):
    resulted_ldif = text_object.get("1.0", tk.END)
    CL = tk.Tk()
    CL.withdraw()
    CL.clipboard_clear()
    CL.clipboard_append(resulted_ldif)


def yes_no(text_object, welcome_box_variable, redmine_box_variable, 
           own_mail_variable, skype_variable, cn_variable, givenname_variable,
           sn_variable, employeetype_variable, organization_variable,
           location_variable, email_variable, password_variable):

    if tkMessageBox.askyesno(title = 'Attention', 
        message = 'Are you sure want to create new user on OpenLDAP/Redmine?', icon = 'warning'):
        #import_to_ldap(text_object)

        # checkbox status
        welcome_box = welcome_box_variable.get()
        redmine_box = redmine_box_variable.get()
        personal_email = own_mail_variable.get()

        # if welcome_box is checked and mail is not null
        if welcome_box:
            if re.match("^[A-Za-z0-9]+@[a-z0-9]+\.[a-z\.]+$", personal_email):
                sent_mail(personal_email, givenname_variable, email_variable,
                          password_variable, cn_variable)
            else:
                tkMessageBox.showerror("Error", "Email is not correct!\nMessage was not sent.")

        if redmine_box:
            create_redmine(cn_variable, password_variable, givenname_variable,
                           sn_variable, email_variable, skype_variable,
                           employeetype_variable, organization_variable, location_variable)

        import_to_ldap(text_object)
    else:
        root.quit

def sent_mail(personal_email, givenname_variable, email_variable,
              password_variable, cn_variable):
    reload(settings)
    sender = "Sysadmins Team"
    to = "Me"
    subject = "Your new mailbox"
    receivers = [personal_email]
     
    headers = "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (sender, to, subject)
    body = (
            "Hello, %s\n\n"
            "Here are your credentials for mailbox:\n\n"
            "login: %s\n"
            "password: %s\n"
            "link https://accounts.google.com for login.\n\n"
            "And this is your access to our issue tracking tool Redmine:\n\n"
            "login: %s\n"
            "password: %s\n"
            "link: %s\n\n" 
            "Feel free to ask any questions.\nBye."
            ) % (givenname_variable, email_variable, password_variable, cn_variable, password_variable, settings.REDMINE_URL)
    msg = headers + body
    
    mailserver = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
    mailserver.ehlo()
    mailserver.starttls()
    mailserver.ehlo()
    mailserver.login(settings.admin_mailbox, settings.admin_mailbox_pw)
    mailserver.sendmail(settings.admin_mailbox, receivers, msg)
    mailserver.close()


def import_to_ldap(text_object):
    reload(settings)
    resulted_ldif = text_object.get("1.0", tk.END)   
    
    # Open a connection
    l = ldap.initialize(settings.ldap_server)
    # Bind/authenticate with a user with apropriate rights to add objects
    l.simple_bind_s(settings.ldap_root_dn, settings.ldap_root_pw)

    ldif_file = StringIO(str(resulted_ldif))
    parser = ldif.LDIFRecordList(ldif_file)
    parser.parse()

    print resulted_ldif
    print "------"
    print(parser.all_records)

    for dn, entry in parser.all_records:
        add_modlist = modlist.addModlist(entry)
        l.add_s(dn, add_modlist)


def create_redmine(cn_variable, password_variable, givenname_variable,
                   sn_variable, email_variable, skype_variable, employeetype_variable,
                   organization_variable, location_variable):

    reload(settings)
    redmine = Redmine(settings.REDMINE_URL, key=settings.REDMINE_KEY, requests={'verify': False})
    warnings.filterwarnings("ignore")

    user = redmine.user.new()
    user.login = cn_variable
    user.password = password_variable
    user.firstname = givenname_variable
    user.lastname = sn_variable
    user.mail = email_variable
    user.custom_fields = [{'id': 10, 'value': skype_variable}, 
                          {'id': 13, 'value': employeetype_variable}, 
                          {'id': 14, 'value': organization_variable}, 
                          {'id': 15, 'value': location_variable}, 
                          {'id': 45, 'value': 0}]
    user.save()


def random_password(N):
    password = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))
    return password


def about_window():
    top2 = tk.Toplevel(root)
    top2.title("About")
    top2.resizable(0,0)
    top2.focus_set()                                                        
    top2.grab_set() 

    top2.tk.call('wm', 'iconphoto', top2._w, logo)

    explanation = """This program is for easy creating accounts 
for new users.

It can create new users in OpenLDAP and 
Redmine through API and uses Tkinter for 
GUI, python-ldap and python-redmine libs"""
    label = ttk.Label(top2, image=logo)
    label.image = logo # keep a reference!
    label.grid(row=0,column=0, pady=4)

    ttk.Label(top2,justify=tk.LEFT,text=explanation).grid(row=0,column=1, padx=6)
    ttk.Button(top2,text='OK',width=10,command=top2.destroy).grid(row=1,column=0, columnspan=2, pady=8)

    

def settings_window():

    reload(settings)

    top3 = tk.Toplevel(root)
    top3.title("Preferances")
    top3.resizable(0,0)
    
    logo = tk.PhotoImage(file="settings.gif")
    top3.tk.call('wm', 'iconphoto', top3._w, logo)

    top3.focus_set()                                                        
    top3.grab_set() 
    
    # Redmine
    group1 = tk.LabelFrame(top3, text="Redmine settings", padx=5, pady=5)
    group1.grid(row=0, column=0, padx=4, pady=4, sticky="we",columnspan=2)

    label(group1, 0, 0, 'URL')
    variable1 = entry(group1, 0, 1, settings.REDMINE_URL)

    label(group1, 1, 0, 'API Key')
    variable2 = entry(group1, 1, 1, settings.REDMINE_KEY)
    #

    # LDAP
    group2 = tk.LabelFrame(top3, text="OpenLDAP settings", padx=5, pady=5)
    group2.grid(row=2, column=0, padx=4, pady=4, sticky="we",columnspan=2)

    label(group2, 2, 0, 'LDAP URL')
    variable3 = entry(group2, 2, 1, settings.ldap_server)

    label(group2, 3, 0, 'Root DN')
    variable4 = entry(group2, 3, 1, settings.ldap_root_dn)

    label(group2, 4, 0, 'Employee DN')
    variable5 = entry(group2, 4, 1, settings.ldap_employees_dn)

    label(group2, 5, 0, 'Password')
    variable6 = entry(group2, 5, 1, settings.ldap_root_pw)
    #

    # SMTP
    group3 = tk.LabelFrame(top3, text="SMTP settings", padx=5, pady=5)
    group3.grid(row=6, column=0, padx=4, pady=4, sticky="we",columnspan=2)

    label(group3, 6, 0, 'Server')
    variable7 = entry(group3, 6, 1, settings.smtp_server)

    label(group3, 7, 0, 'Port')
    variable8 = entry(group3, 7, 1, settings.smtp_port)

    label(group3, 8, 0, 'Mailbox')
    variable9 = entry(group3, 8, 1, settings.admin_mailbox)

    label(group3, 9, 0, 'Mailbox password')
    variable10 = entry(group3, 9, 1, settings.admin_mailbox_pw)
    #

    # Mail domain 
    group4 = tk.LabelFrame(top3, text="Mail domain", padx=5, pady=5)
    group4.grid(row=10, column=0, padx=4, pady=4, sticky="we",columnspan=2)

    label(group4, 10, 0, 'Mail domain')
    variable11 = entry(group4, 10, 1, settings.mail_domain)  
    #


    label(top3, 11, 0, ' ')

    button(top3, 12, 0, 'Apply', lambda: save_settings(variable11.get(),variable1.get(),variable2.get(),
                                        variable3.get(),variable4.get(),variable5.get(),variable6.get(),
                                        variable7.get(),variable8.get(),variable9.get(),variable10.get()), sticky="w")
    button(top3, 12, 1, 'Quit', top3.destroy)


def save_settings(mail_domain, REDMINE_URL, REDMINE_KEY, ldap_server, 
    ldap_root_dn, ldap_employees_dn, ldap_root_pw, smtp_server, smtp_port,
    admin_mailbox, admin_mailbox_pw):

    # clean file
    open('settings.py', 'w').close()

    with open('settings.py', 'a') as the_file:
        the_file.write("mail_domain = '%s'\n" % mail_domain)
        the_file.write("REDMINE_URL = '%s'\n" % REDMINE_URL)
        the_file.write("REDMINE_KEY = '%s'\n" % REDMINE_KEY)
        the_file.write("ldap_server = '%s'\n" % ldap_server)
        the_file.write("ldap_root_dn = '%s'\n" % ldap_root_dn)
        the_file.write("ldap_root_pw = " + '"' + ldap_root_pw + '"' + '\n')
        the_file.write("ldap_employees_dn = '%s'\n" % ldap_employees_dn)
        the_file.write("smtp_server = '%s'\n" % smtp_server)
        the_file.write("smtp_port = %d\n" % int(smtp_port))
        the_file.write("admin_mailbox = '%s'\n" % admin_mailbox)
        the_file.write("admin_mailbox_pw = '%s'" % admin_mailbox_pw)


root = tk.Tk()
root.resizable(0,0)

root.style = ttk.Style()
# ('clam', 'alt', 'default', 'classic')
root.style.theme_use("clam")

# main window
root.title("LDAP Adder")
# app icon
logo = tk.PhotoImage(file='ldap_adder.gif')
root.tk.call('wm', 'iconphoto', root._w, logo)


label(root, 0, 0, 'First name')
var0 = entry(root, 0, 1)

label(root, 1, 0, 'Second name')
var1 = entry(root, 1, 1)

label(root, 2, 0, 'Country (two letters)')
var2 = entry(root, 2, 1)

label(root, 3, 0, 'City')
var3 = entry(root, 3, 1)

label(root, 5, 0, 'Accessible Host')
var5 = entry(root, 5, 1, "example.com")

label(root, 6, 0, 'Organization')
var6 = entry(root, 6, 1, "Company")

options = [
    "Top management",
    "Indoor Project Manager",
    "Indoor Developer",
    "Indoor Designer",
    "Indoor QA responsible",
    "Indoor Front-end developer",
    "Indoor System Administrator",
    "Outdoor Developer",
    "Outdoor Front-end developer",
    "Outdoor Flash Developer",
    "Outdoor Center Manager",
    "Outdoor Designer",
    "Outdoor QA responsible",
    "Outdoor Ruby Developer",
    "Outdoor C/C++/Objective C developer",
    "Outdoor System Administrator",
    "Client",
    "Client CTO",
    "Client Sales",
    "Client Functional manager",
    "Client Technical manager",
    "Client Top Management"
]

label(root, 7, 0, 'Employee type')
var7 = tk.StringVar(root)

w = apply(ttk.OptionMenu, (root, var7) + tuple(options))
w.grid(row=7,column=1, sticky="ew", padx=4, pady=1)
var7.set(options[2]) # default value

label(root, 8, 0, 'Skype')
var8 = entry(root, 8, 1)

label(root, 9, 0, 'Phone')
var9 = entry(root, 9, 1)

# SSH key field
label(root, 10, 0, 'SSH Key')
# This code is for adding borders to text field.
# w/o it text field looks pretty bad in OS X
left_outer = tk.Frame(root, bd=2)
left_outer.grid(row=10,column=1)
left = tk.Frame(left_outer, bd=2, relief=tk.RIDGE)
left.grid(row=10,column=1)
#

var10 = text_field_w_scroll(left, 34, 5, "ssh-rsa key", 10, 1, 2)

label(root, 11, 0, 'POSIX UID')
var11 = entry(root, 11, 1)

#label(root, 12, 0, 'Password')
#var12 = entry(root, 12, 1, show='*')

label(root, 13, 0, '')

button(root, 14, 0, 'Show', show_ldif)
button(root, 14, 1, 'Close', root.quit)

# Menu
menu = tk.Menu(root)
root.config(menu=menu)
 
fm = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="Settings",menu=fm)
fm.add_command(label="Preferances",command=settings_window)
 
hm = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="Help",menu=hm)
hm.add_command(label="About", command=about_window)
hm.add_command(label="Exit",command=root.quit)
#

tk.mainloop()