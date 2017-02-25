from setuptools import setup, find_packages

setup(name='awsbb',
version='0.0.3',
description='A tool to audit your AWS credentials',
license='MIT',
url='https://github.com/jae2/awsbigbrother',
long_description="A command line app which allows you to check users compliance with various security policies",
install_requires=['click','boto3','arrow','configparser','six'],
packages=find_packages(exclude=['contrib', 'docs', 'test*','venv*','build','dist','.cache','fixtures','.cache']),
author_email='admin@jaetech.org',
author='James Edwards',
entry_points={
    'console_scripts': [
    'awsbb=awsbigbrother.cli:app',
    ]
},
classifiers=[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
]
)
