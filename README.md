# AWS Big Brother is always watching!


[![Build Status](https://travis-ci.org/jedops/awsbigbrother.svg?branch=master)](https://travis-ci.org/jedops/awsbigbrother)

![Big Brother is always watching!](https://github.com/jedops/awsbigbrother/blob/master/assets/eye-309755_1280.png?raw=true)


## What is it?

A lightweight command line tool to analyse IAM users. To audit IAM user accounts you can either supply various command line options or set up a configuration file. AWS Big brother is designed to be run regularly by some kind of monitoring tool. Of course there's nothing stopping you just running it on your own machine.

## What can I do with it?

At present it can be configured to error on the below and display the users who failed the check. If you don't wish to print the user list this can also be configured.

- User does not have MFA enabled.
- User has not changed their password in N days.
- User has not rotated their access keys in N days.
- User has not had any activity in N days.
- User has not rotated their certs in N days.
- User does not have policy x.

## Installation:

``` pip install awsbb ```

## Example usage


To begin with you'll need to setup some AWS credentials. My preferred way is to have a profiles in ~/.aws/credentials and run ```AWS_PROFILE=myprofile``` before each command. You can either set up your creds via the [awscli](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) or run the following

``` 
export AWS_ACCESS_KEY_ID=myaccess_key_remember_to_keep_it_secret
export AWS_SECRET_ACCESS_KEY=secret_key_remember_to_keep_it_secret

```
Show me all users who do not have MFA set:

``` awsbb --mfa ```

Show me all users who don't have MFA set and also show me users who have not changed their password in 30 days:

``` awsbb --mfa --password_max_age 30 ```

Run the same check above, don't print the list of users for whom the check failed, but still exit with an error:

``` awsbb --mfa --password_max_age 30 --noout ```

Show me all users who don't have MFA set and also show me users who have not rotated their access keys in 30 days:

``` awsbb --mfa --access_key_max_age 30 ```

Show me all users who don't have MFA set excluding app1user and app2user:

``` awsbb --mfa -e app1user,app2user ```

Show me all users who don't have the policy "force_mfa" set

``` awsbb --mfa --expected_policies "policy1,policy2" ```




## Using a configuration file:

A sample configuration file is available [here](https://raw.githubusercontent.com/jae2/awsbigbrother/master/examples/audit.conf).

Note the order of precedence for options is as follows:

1. Command line arguments
2. Configuration files
3. Default values

To pass a configuration file in at runtime:

``` awsbb -c path/to/config/file ```

