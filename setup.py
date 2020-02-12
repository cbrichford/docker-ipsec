from setuptools import setup

setup(
    name='docker-ipsec',
    version='3.0.0',
    description='Scripts to start/stop ipsec VPN tunnels while adding/removing iptables rules for docker networking.',
    author='Christopher Brichford',
    author_email='chrisb@farmersbusinessnetwork.com',
    license='Apache License 2.0',
    keywords=['ipsec', 'docker'],  # arbitrary keywords
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Topic :: Internet',
        'Topic :: System :: Networking'
    ],
    scripts=['docker_ipsec/docker-ipsec.py'],
    install_requires=[
        'pyroute2>=0.5.7,<0.6.0',
        'netaddr>=0.7.19,<0.8.0',
        'python-iptables>=0.14.0,<0.15.0',
        'ipsecparse',
        'docker>=4.2.0,<4.3.0'
    ],
    url='https://github.com/cbrichford/docker-ipsec/',
    packages=[
        'docker_ipsec'
    ],
)
