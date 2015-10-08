from distutils.core import setup
setup(
  name = 'docker-ipsec',
  version = '0.1',
  description = 'Scripts to start/stop ipsec VPN tunnels while adding/removing iptables rules for docker networking.',
  author = 'Christopher Brichford',
  author_email = 'chrisb@farmersbusinessnetwork.com',
  license='Apache License 2.0',
  keywords = ['ipsec', 'docker'], # arbitrary keywords
  classifiers = [],
  scripts=['docker_ipsec/docker-ipsec.py'],
  install_requires=['pyroute2', 'netaddr', 'python-iptables', 'ipsecparse'],
  packages=[
        'docker_ipsec'
    ],
)
