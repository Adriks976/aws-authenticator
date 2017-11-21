#!/usr/local/bin/python

import hmac, base64, struct, hashlib, time, re, sys
import os
import boto3
from keyring import get_password, set_password
from configparser import ConfigParser
import argparse
import getpass

def get_token(secret):
	secret = re.sub(r'\s+', '', secret, flags=re.UNICODE)
	secret += '=' * ((8 - len(secret) % 8) % 8)
	key = base64.b32decode(secret, True)
	msg = struct.pack(">Q", int(time.time())//30)
	h = hmac.new(key, msg, hashlib.sha1).digest()
	o = h[19] & 15
	#o = ord(h[19]) & 15
	h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
	return '{0:06d}'.format(h)

def get_secret(file, base_profile):
	secret = get_password("aws-" + base_profile, base_profile)
	if secret: 
		return secret
	else: 
		sys.exit('No secret in keychain found')
		
	

def get_profile(file, profile):
	if not os.path.isfile(file):
		sys.exit('Error: Need to check existence of your file')
		
	config = ConfigParser()
	config.read(file)
	if profile in config.sections():
		return profile
	else:
		sys.exit('Error: No profile matched yours in .aws/credentials')



def get_credentials(profile,secret):
	session = boto3.Session(profile_name=profile)
	sts_connection = session.client('sts')
	iam_connection = session.client('iam')
	mfa_TOTP = get_token(secret)

	user = iam_connection.get_user()
	user = user["User"]["UserName"]

	mfa_device = iam_connection.list_mfa_devices(UserName=user)
	mfa_device = mfa_device["MFADevices"][0]["SerialNumber"]

	return sts_connection.get_session_token(
		            DurationSeconds=86400,
			    SerialNumber=mfa_device,
			    TokenCode=mfa_TOTP)


def update_credentials(file, mfa_profile, credentials):
	config = ConfigParser()
	config.read(file)
	if not config.has_section(mfa_profile):
		config.add_section(mfa_profile)
	config[mfa_profile]['aws_access_key_id'] = credentials["AccessKeyId"]
	config[mfa_profile]['aws_secret_access_key'] = credentials["SecretAccessKey"]
	config[mfa_profile]['aws_session_token'] = credentials["SessionToken"]
	with open(file, 'w') as configfile:
		config.write(configfile)


def store_secret(profile, secret):
	set_password("aws-" + profile, profile, secret)


if __name__ == "__main__":
#	parser.add_argument('-g', '--generate-profile', nargs=2, metavar=('ACCESS_KEY', 'SECRET_KEY'),  help='create base profile with your access key and secret key')
	
	parser = argparse.ArgumentParser(description='Manage AWS profiles with MFA enabled')
	optional = parser._action_groups.pop() 
	required = parser.add_argument_group('required argument')
	required.add_argument('base_profile', type=str, help='name of your base profile')

	optional.add_argument('-g', '--generate-profile', type=str, metavar='mfa_profile', help='name of your mfa profile you want to create')
	optional.add_argument('-s', '--store-secret', help='save secret in keychain', action='store_true')

	parser._action_groups.append(optional) 
	args = parser.parse_args()
	
	if args.store_secret:
		secret=getpass.getpass("Enter Your Secret Here: ")
		store_secret("%s" % args.base_profile, secret)
		print("Your secret is successfully registered in your keychain")
	elif args.generate_profile:
		credentials_file = os.path.expanduser('~/.aws/credentials')
		profile = get_profile(credentials_file, "%s" % args.base_profile)
		secret = get_secret(credentials_file, profile)
	
		tempCredentials = get_credentials(profile,secret)
	
		cred = tempCredentials["Credentials"]
	
		update_credentials(credentials_file, "%s" % args.generate_profile, cred)
		print("Sucess!")
		print(" On your terminal type:\n export AWS_PROFILE=%s\n to load your credentials" % args.generate_profile)
		
	else:
		credentials_file = os.path.expanduser('~/.aws/credentials')
		profile = get_profile(credentials_file, "%s" % args.base_profile) 
		secret = get_secret(credentials_file, profile)
		print("Token: "+ get_token(secret))	

	
