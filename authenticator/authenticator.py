#!/usr/local/bin/python

import hmac, base64, struct, hashlib, time, re, sys
import os
import boto3
from keyring import get_password
from configparser import ConfigParser

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

def get_secret(file,profile):
	secret = get_password("aws-" + profile, profile)
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
		            DurationSeconds=3600,
			    SerialNumber=mfa_device,
			    TokenCode=mfa_TOTP)


def update_credentials(file, profile, credentials):
	config = ConfigParser()
	config.read(file)
	config[profile + '-mfa']['aws_access_key_id'] = credentials["AccessKeyId"]
	config[profile + '-mfa']['aws_secret_access_key'] = credentials["SecretAccessKey"]
	config[profile + '-mfa']['aws_session_token'] = credentials["SessionToken"]
	with open(file, 'w') as configfile:
		config.write(configfile)




def main():
	
	credentials_file = os.path.expanduser('~/.aws/credentials')
	profile = get_profile(credentials_file, sys.argv[1]) 
	secret = get_secret(credentials_file, profile)
	
	tempCredentials = get_credentials(profile,secret)
	
	print(tempCredentials)

	cred = tempCredentials["Credentials"]
	update_credentials(credentials_file, profile, cred)


if __name__ == "__main__":
	main()
