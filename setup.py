from setuptools import setup, find_packages

setup(name='awsbb',
version='0.0.1',
description='A tool to audit your AWS credentials',
long_description="Big brother is always watching you :)",
install_requires=['click','boto3','arrow'],
packages=find_packages(exclude=['contrib', 'docs', 'test*','venv','build','dist','.cache','fixtures']),
entry_points={
    'console_scripts': [
    'awsbb=awsbigbrother.cli:app',
    ]
}

)
