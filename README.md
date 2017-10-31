# aws-authenticator
manage credentials file, generate MFA tokens

A Python script wich help you managing your AWS credentials with your MFA tokens.
To use MFA on AWS you can use a virtual device like Google authenticator or you can just use this script.

To install dependencies:

pip3 install -r requirements.txt

Configuration required

- aws credentials file : ~/.aws/crendentials
- profiles 

example: 

[profile1]
aws_access_key_id = XXXXXXXXXXXXXXXXX
aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

[profile2]
aws_access_key_id = XXXXXXXXXXXXXXXXX
aws_secret_access_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

You need to store your secret in your keychain:




