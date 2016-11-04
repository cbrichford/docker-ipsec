from setuptools import setup
setup(
  name = 'docker-ipsec',
  version = '2.0.0',
  description = 'Scripts to start/stop ipsec VPN tunnels while adding/removing iptables rules for docker networking.',
  author = 'Christopher Brichford',
  author_email = 'chrisb@farmersbusinessnetwork.com',
  license='Apache License 2.0',
  keywords = ['ipsec', 'docker'], # arbitrary keywords
  classifiers = [
    'Development Status :: 3 - Alpha',
    'Environment :: Console',
    'Intended Audience :: Information Technology',
    'License :: OSI Approved :: Apache Software License',
    'Operating System :: POSIX :: Linux',
    'Topic :: Internet',
    'Topic :: System :: Networking'
  ],
  scripts=['docker_ipsec/docker-ipsec.py'],
  install_requires=['pyroute2', 'netaddr', 'python-iptables', 'ipsecparse', 'docker-py'],
  url='https://github.com/cbrichford/docker-ipsec/',
  packages=[
        'docker_ipsec'
    ],
)
