from setuptools import setup, find_packages

# Define your dependencies in the `install_requires` list
# If you have more dependencies, add them here
install_requires = [
    'pycryptodome~=3.18.0',
    'SEEV-base-cryptography~=0.0.1a'
]

setup(
    name='SEEV-verifier',
    version='0.0.1',  # Adjust the version as necessary
    description='Implementation of the SEEV DRE-IP verifier software',
    author='Timothee Dubuc',
    author_email='timothee@global-initiative.com',
    packages=find_packages(),
    python_requires='~=3.10.13',  # Specify the exact Python version required
    install_requires=install_requires,
    classifiers=[
        'Development Status :: 3 - Alpha',  # Change as appropriate
        'Intended Audience :: Developers',
        # 'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
    ],
)

