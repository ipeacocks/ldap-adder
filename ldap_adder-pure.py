import Tkinter as tk
import tkMessageBox

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
import settings


def label(root, row, column, text):
    L = tk.Label(root, text=text, anchor='w')
    L.grid(row=row,column=column,sticky="nw",padx=3)


def button(root, row, column, text, command, columnspan=1, sticky="e"):
    B = tk.Button(root, text=text, command=command, width=20)
    B.grid(row=row, column=column, sticky=sticky, pady=4, columnspan=columnspan, padx=4)


def entry(root, row, column, insert="", show=""):
    E = tk.Entry(root, width=32)
    E.insert(0, insert)
    E.config(show=show)
    E.grid(row=row,column=column, padx=2)
    return E

def check_box(root, row, column, text, variable, columnspan=1):
    CB = tk.Checkbutton(root, text=text, variable=variable)
    CB.grid(row=row, column=column, sticky="w", columnspan=columnspan, padx=4, pady=1)


def text_field_w_scroll(root, width, height, text, row, column, column_scroll, columnspan=1):
    text_field = tk.Text(root, width=width, height=height)
    text_field.insert(tk.END, text)
    text_field.grid(row=row, column=column, columnspan=columnspan)
    scroll = tk.Scrollbar(root)
    scroll.config(command=text_field.yview)
    scroll.grid(row=row, column=column_scroll, sticky="nes")
    text_field.config(yscrollcommand=scroll.set)
    return text_field


def show_ldif():

    givenname = var0.get()
    sn = var1.get()
    country = var2.get()
    location = var3.get()
    #address = var4.get()
    accessible_host = var5.get()
    organization = var6.get()
    employeetype = var7.get()
    skype = var8.get()
    phone = var9.get()
    ssh_key = var10.get("1.0", tk.END)
    # fixme: why new line in the end of text widget?
    ssh_key = ssh_key.rstrip('\n')
    password = random_password(8)
    cn = givenname[0].lower() + sn.lower()
    email = cn + '@' + settings.mail_domain   
    uidnumber = var11.get()

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

    top = tk.Toplevel()
    top.title("Result")
    top.resizable(0,0)

    ldif_text = text_field_w_scroll(top, 67, 27, ldif, 0, 0, 2, 2)

    var13 = tk.IntVar()
    check_box(top, 2, 0, "Send welcome mail", var13)
    var14 = entry(top, 2, 1, "example@mail.ru")
    var15 = tk.IntVar()
    check_box(top, 1, 0, "Create Redmine account", var15)
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
        message = 'Are you sure want to create new user on Webmail/Redmine?', icon = 'warning'):
        import_to_ldap(text_object)

        # checkbox status
        welcome_box = welcome_box_variable.get()
        redmine_box = redmine_box_variable.get()
        personal_email = own_mail_variable.get()

        # if welcome_box is checked and mail is not null
        if personal_email:
            if welcome_box:
                sent_mail(personal_email, givenname_variable, email_variable,
                          password_variable, cn_variable)
            if redmine_box:
                create_redmine(cn_variable, password_variable, givenname_variable,
                               sn_variable, email_variable, skype_variable,
                               employeetype_variable, organization_variable, location_variable)
    else:
        root.quit

def sent_mail(personal_email, givenname_variable, email_variable,
              password_variable, cn_variable):
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
            "link https://roundcube.company.com for login.\n\n"
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


root = tk.Tk()
root.resizable(0,0)
# main window
root.title("LDAP Adder")
# app icon
img = tk.PhotoImage(file='ldap_adder.gif')
root.tk.call('wm', 'iconphoto', root._w, img)


label(root, 0, 0, 'First name')
var0 = entry(root, 0, 1)

label(root, 1, 0, 'Second name')
var1 = entry(root, 1, 1)

label(root, 2, 0, 'Country (two letters)')
var2 = entry(root, 2, 1)

label(root, 3, 0, 'City')
var3 = entry(root, 3, 1)

#label(4, 0, 'Address')
#var4 = entry(4, 1)

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
var7.set(options[0]) # default value

w = apply(tk.OptionMenu, (root, var7) + tuple(options))
w.grid(row=7,column=1, sticky="ew")

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
button(root, 14, 1, 'Quit', root.quit)

tk.mainloop()