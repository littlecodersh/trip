""" 
See:
https://github.com/littlecodersh/trip
"""

from setuptools import setup, find_packages
from codecs import open
from os import path
import trip

here = path.abspath(path.dirname(__file__))
about = {}

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, 'trip', '__version__.py'), 'r', 'utf-8') as f:
    exec(f.read(), about)

setup(
    name='trip',

    version=about['__version__'],
    description='Async HTTP for humans, coroutine Requests.',
    long_description=long_description,

    url='https://github.com/littlecodersh/trip',

    author='LittleCoder',
    author_email='i7meavnktqegm1b@qq.com',

    license='Apache 2.0',

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],

    keywords='coroutine requests http spider',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(),

    install_requires=[
        'requests>=2.18.4',
        'tornado==4.5.3'
    ],

    # List additional groups of dependencies here
    extras_require={},
)
