#!/usr/bin/env python3
from OpenSSL import crypto
import argparse
import os,sys

# Command line arguments
parser = argparse.ArgumentParser(description='''
Script for SSL Certificate CSR and key generating

The most of parameteres, that usually used as fields in CSR, are already given with default values. If you want to change them, you can use optional arguments, that are given below
''')
parser.add_argument('--cn',
                    '-c',
                    type=str,
                    required=True, 
                    help='The fully-qualified domain name (FQDN) (e.g., www.example.com).')

parser.add_argument('--email',
                    '-e',
                    type=str,
                    nargs='?',
                    help='E-mail address', 
                    default='support@itsyndicate.org')

parser.add_argument('--country',
                    '-C',
                    type=str,
                    nargs='?',
                    help='The two-letter country code where your company is legally located.', 
                    default='US')

parser.add_argument('--state',
                    '-s',
                    type=str,
                    nargs='?',
                    help='The state/province where your company is legally located.', 
                    default='Texas')

parser.add_argument('--location',
                    '-l',
                    type=str,
                    nargs='?',
                    help='The city where your company is legally located.', 
                    default='Houston')
parser.add_argument('--organization',
                    '-o',
                    type=str,
                    nargs='?',
                    help='The name of your department within the organization', 
                    default='Some department')

args = parser.parse_args()

cn = args.cn
email = args.email
C = args.country
ST = args.state
L = args.location
OU = args.organization

# Checking if directory ~/SSL exists, if not , then create it.
ssl_dir = os.getenv('HOME') + '/SSL'
if not os.path.exists(ssl_dir):
    os.makedirs(ssl_dir)

# function that creates and prints to stdout CSR and key files
def gencsrfiles(cn, email, C, ST, L, OU):
    # Create all needed directory
    result_dir = ssl_dir + '/' + cn
    if not os.path.exists(ssl_dir + '/' +cn):
        os.makedirs(ssl_dir + '/' +cn)
    csr_file = result_dir + '/' + cn + '.csr'
    key_file = result_dir + '/' + cn + '.key'

    # Generate key and csr
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    # print(key())
    csr = crypto.X509Req()
    csr.get_subject().CN = cn
    csr.get_subject().C = C
    csr.get_subject().ST = ST
    csr.get_subject().L = L
    csr.get_subject().OU = OU
    csr.get_subject().emailAddress = email
    csr.set_pubkey(key)
    csr.sign(key, 'sha1')

    # Save results to files and print them to stdout
    with open(csr_file, 'wb') as csr_f:
        csr_f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))
    with open(key_file, 'wb') as key_f:
        key_f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    print("  \n")    
    print("          ██████╗███████╗██████╗  ")
    print("         ██╔════╝██╔════╝██╔══██╗ ")
    print("         ██║     ███████╗██████╔╝ ")
    print("         ██║     ╚════██║██╔══██╗ ")
    print("         ╚██████╗███████║██║  ██║ ")
    print("          ╚═════╝╚══════╝╚═╝  ╚═╝ \n")        
    sys.stdout.buffer.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))
    print(" \n")
    print("         ██╗  ██╗███████╗██╗   ██╗")
    print("         ██║ ██╔╝██╔════╝╚██╗ ██╔╝")
    print("         █████╔╝ █████╗   ╚████╔╝ ")
    print("         ██╔═██╗ ██╔══╝    ╚██╔╝  ")
    print("         ██║  ██╗███████╗   ██║   ")
    print("         ╚═╝  ╚═╝╚══════╝   ╚═╝   \n")    
    sys.stdout.buffer.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

gencsrfiles(cn, email, C, ST, L, OU)
