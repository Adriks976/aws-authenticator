# AWS Authenticator

> Manage AWS credentials, generate MFA tokens

A Python script wich help you managing your AWS credentials with your MFA tokens.
To use MFA on AWS you can use a virtual device like Google authenticator or you can just use this script.

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Security

### MFA Token

In order to provide the maximum level of security, the MFA secret token is stored in your Keychain (Mac).

### AWS Credentials

Permanent and temporary AWS Credentials are stored in `~/.aws/credentials`.

## Background

In order to use the [aws-cli](https://aws.amazon.com/cli/) with Multi-Factor Authentication, you need to generate new session credentials everyday. This tools has be developed to get rid of the repetitive task of logging in and retreiving MFA token.

## Install

This module requires [Python 3](https://www.python.org/downloads/).
You can [download it](https://www.python.org/downloads/) or install it with brew on Mac.

```
$ brew install python3
```

Clone this repository and install `pip` dependencies:

```
$ git clone https://github.com/Adriks976/aws-authenticator.git
$ cd aws-authenticator
$ pip3 install -r requirements.txt
```

### Setup AWS profils

Edit the `~/.aws/crendentials` with your AWS credentials. Access key and secret key can be found in the [IAM console](https://console.aws.amazon.com/iam/home?#home) ([tutorial](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html))

```ini
# ~/.aws/credentials
[profil1]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
```

or using the `aws cli`:

```
$ aws configure --profile profile1
AWS Access Key ID [None]: AKIAI44QH8DHBEXAMPLE
AWS Secret Access Key [None]: je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
Default region name [None]: us-east-1
Default output format [None]: text
```

## Usage

```
usage: authenticator.py [-h] [-g mfa_profile] [-s] base_profile

Manage AWS profiles with MFA enabled

required argument:
  base_profile          name of your base profile

optional arguments:
  -h, --help            show this help message and exit
  -g mfa_profile, --generate-profile mfa_profile
                        name of your mfa profile you want to create
  -s, --store-secret    save secret in keychain
```

### Store the MFA secret in the Keychain

```
$ authenticator.py profile1 --store-secret
Enter Your Secret Here:🔑
Your secret is successfully registered in your keychain
```

### Generate a MFA token

Generates a token that can be used for login your AWS account.

```
$ authenticator.py profile1
Token: 130528
```

### Generate AWS session credentials

This command generates temporary credentials and store them in a 2nd profile.

```
$ authenticator.py profile1 --generate-profile profile1_mfa
Sucess!
On your terminal type:
export AWS_PROFILE=profile1_mfa
to load your credentials
```

A second profile is created, adding the session token.

```ini
# ~/.aws/credentials
[profile1]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY

[profile1_mfa]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token = exampleC8aDMBsG5Ha9J/KzfSuHyKwexamplex3vg+knx7CJEnTSGGf3pmEWFuMS3dLUWlVgmIGaIv6ELrL/7ZVfVPIwOgGi8JrBX9UpI9VCHCnX+Ogb0TyiZasLsaFP9k1cFXBTiHve1agOW7b8IWVUzexample1C112M2gjxOEk9oFxgqGfZVHp7Zk4R6iTgQ9HckxoIZ/c4vhwL6Sfexamplefc3FOGgZhlcMFSrIr5tUwHeLRoOYqtzJDGMAsaoTyrvKJHttdQF
```

## Contribute

PRs accepted.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT](LICENSE)
