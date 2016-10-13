#!/usr/bin/env python
# Script to retrieve data from IEM by MAC address or ID
import os, keyring, getpass, sys, requests 
from optparse import OptionParser
from requests.auth import HTTPBasicAuth
from xml.etree import cElementTree, ElementTree
# Disable certificate warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# Define function for getting xml from IEM
def get_xml(url, parms):
    response = requests.get(url + parms, auth=HTTPBasicAuth(options.username, password), verify=False)
    resp_xml = ElementTree.fromstring(response.content)
    return resp_xml;
# Parse command line args
parser = OptionParser()
parser.add_option("--user", dest="username")
parser.add_option("--mac", dest="mac_address")
parser.add_option("--id", dest="iem_id")
(options, args) = parser.parse_args()
# Make the user argument required
if not options.username:   
    parser.error('Username required')
# Either a MAC address or IEM Computer ID is also required
if not options.mac_address and not options.iem_id:   
    parser.error('MAC or ID required')
# Retrieve the scriptname - this will be used for storing credentials in the keyring
script_name = os.path.basename(__file__)

# Retrieve a password for the user from the keyring
try:
    password = keyring.get_password(script_name, options.username)
    if password == None:
     raise ValueError("Password not in keyring") 
except ValueError as err:
# If the password was None, prompt for a password and store it in the keyring
    password = getpass.getpass(prompt='Password: ')
    keyring.set_password(script_name, options.username, password)
except :   
 print("Unexpected error:", sys.exc_info()[0])
 raise
# Format the mac address and execute a relevance query to lookup the IEM computer ID
mac_address = "-".join(options.mac_address.split(":")).lower()
compid_relq = "(maximum of ids of it) of computers of results whose(value of it contains \"%s\") of bes  property \"MITLL::Registration MAC\" " % mac_address
id_xml = get_xml("https://iem.local:52311/api/query?relevance=",compid_relq)
compid = id_xml.find("Query/Result/Answer").text
# Execute a second IEM query to retrieve all computer properties
comp_xml = get_xml("https://iem.local:52311/api/computer/",compid)
for el in comp_xml:
 comp = {ch.attrib.get('Name'): ch.text for ch in el.getchildren()}
 # Strip leading zeros from propertynumber
 comp['propPropertyNum'] = comp['propPropertyNum'].lstrip("0")
# Identify OS and execute hardware information query
 if "mac" in comp['OS'].lower():
    hw_type = "Mac OS X"
 elif "win" in comp['OS'].lower(): 
    hw_type = "Windows"
 elif "linux" in comp['OS'].lower(): 
    hw_type = "Linux"
hw_relq = "values of results (properties of BES fixlets whose (analysis flag of it and name of it =  \"Hardware Information (%s)\"),bes computer whose (id of it = (" % hw_type + compid + ")))" 
hw_xml = get_xml("https://iem.local:52311/api/query?relevance=", hw_relq)
# Identify form factor from hardware information query
if hw_type == "Mac OS X":
    comp['Manufacturer'] = "Apple"
    comp['Type'] = hw_xml.findall("Query/Result/Answer")[3].text
    if "book" in comp['Type'].lower():
        comp['Form Factor'] = "Laptop"
    else:
        comp_['Form Factor'] = "Workstation"
elif hw_type == "Windows":
    comp['Manufacturer'] = hw_xml.findall("Query/Result/Answer")[0].text
    comp['Type'] = hw_xml.findall("Query/Result/Answer")[1].text
    if hw_xml.findall("Query/Result/Answer")[3].text == "True":
        comp['Form Factor'] = "Laptop"
    else:
        comp['Form Factor'] = "Workstation"
elif hw_type == "Linux":
    comp['Manufacturer'] = hw_xml.findall("Query/Result/Answer")[0].text.split("-")[0]
    comp['Type'] = hw_xml.findall("Query/Result/Answer")[0].text.split("-")[1].strip()
    if hw_xml.findall("Query/Result/Answer")[1].text == "True":
        comp['Form Factor'] = "Laptop"
    else:
        comp['Form Factor'] = "Workstation"
comp['Model'] = comp['Type']
display_values = { 'ID','DNS Name', 'OS', 'Asset', 'Serial', 'user', 'Department', 'Registration MAC', 'Registration IP', 'Device Type', 'User Name', 'Manufacturer', 'Type', 'Model', 'Form Factor'}
disp_output = { key:value for key,value in comp.items() if key in display_values }
for key, value in disp_output.iteritems():
  print key.ljust(25), ":", value
