import setuptools

def readme():
    with open('README.md') as f:
        return f.read()

setuptools.setup(
    name='oraclecloud',
    version='0.2',
    description='Library for Oracle Public Cloud solutions',
    long_description=readme(),
    classifiers=[
    'Development Status :: 3 - Alpha',
    'License :: OSI Approved :: MIT License',
    'Intended Audience :: Developers',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Topic :: Software Development'
    ],
    url='https://github.com/waslleysouza/oraclecloud',
    author='Waslley Souza',
    author_email='waslleys@gmail.com',
    license='MIT',
    packages=setuptools.find_packages(),
    install_requires=[
        'numpy',
        'pycrypto',
        'requests'
    ],
    include_package_data=True,
    zip_safe=False)