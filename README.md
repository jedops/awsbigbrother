# AWS Big Brother is always watching!


[![Build Status](https://travis-ci.org/jae2/awsbigbrother.svg?branch=master)](https://travis-ci.org/jae2/awsbigbrother)

![Big Brother is always watching!](https://github.com/jae2/awsbigbrother/blob/master/assets/eye-309755_1280.png?raw=true)


A lightweight commandline tool to analyse IAM users. 


Usage: awsbb [OPTIONS]

  AWS Credentials reporter. This command checks your AWS account users for
  security issues. Options can either be specified as command line arguments
  or in a configuration file. The order of precedence is as follows:

1. Command line arguments
2. Configuration files
3. Default values

Options:
  -c PATH                        Path to a security check configuration file
  
  --mfa                          Check whether each user has Multi-factor auth
                                 setup
                                 
  -e TEXT                        Users to exclude from the reporting
  
  --access_keys_max_age INTEGER  The maximum age of any access keys the user
                                 has configured
                                 
  --password_max_age INTEGER     The maximum age of a password in days. If the
                                 password has not been changed in this amount
                                 of days the command will report an issue
                                 
  --noout                        Don't print out the check results to the
                                 console (e.g. if you run this on a public
                                 service)
                                 
  --help                         Show help and exit.

