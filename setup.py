from setuptools import setup, find_packages

setup(name='awsbb',
version='0.0.1',
description='A tool to audit your AWS credentials',
license='MIT',
long_description="A command line app which allows you to check users comliance with various security policies",
install_requires=['click','boto3','arrow','configparser'],
packages=find_packages(exclude=['contrib', 'docs', 'test*','venv*','build','dist','.cache','fixtures','.cache']),
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
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
]
)
