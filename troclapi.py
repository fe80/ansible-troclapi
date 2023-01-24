#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import ansible
from ansible.module_utils.basic import AnsibleModule
from packaging import version

# Import json and yaml as custom names to avoid lib
# issues with Ansible
import json as lib_json
import yaml as lib_yaml

# Only required for Ansible >= 2.12, else we can pass
try:
  from ansible.module_utils.common import json
  from ansible.module_utils.common import yaml
except:
  pass


DOCUMENTATION = '''
---
module: trolcapi
short_description: "Troclapi usage for Ansible"
description:
  - "Ansible module to connect to troclapi. Please see api documentation for more informations https://claranet.pages.fr.clara.net/rmp/cs-webops-ga/puppet/tools/projects/troclapi/"  # noqa: E501
author: Fe80
options:
  token:
    description: "admin troclapi token"
    default: "{ 'credentials': secret, 'vautl_pass': '/etc/ansible/vault_pass.py', 'vault': False } secret variable is define on module script"
    required: false
    type: dict
  url:
    description: "troclapi url"
    default: "https:// + NDD variable on module script"
    required: false
    type: str
  action:
    description: "trocla action"
    choices:
      - get
      - create
      - set
      - reset
      - delete
    default: get
    required: false
    type: str
  key:
    description: "trocla key name"
    default: None
    required: true
    type: str
  format:
    description: "trocla format key"
    default: plain
    required: false
    type: str
  render:
    description: "render option for get value"
    choices:
      - certonly
      - keyonly
    default: None
    required: false
    type: str
  options:
    description: "trocla options, see api documentation for more information"
    type: dict
    required: false
    default: {}
'''

EXAMPLES = '''
- name: Get trocla plain value for key toto
  troclapi:
    key: toto
  register: toto_trocla
  delegate_to: localhost
  become: false

- name: Show toto key value
  debug:
    msg: toto_trocla.value

- name: Get trocla x509 cert value for key bob
  troclapi:
    key: bob
    render: certonly
  register: bob_trocla
  delegate_to: localhost
  become: false

- name: Show bob x509 cert value
  debug:
    msg: bob_trocla.value

- name: Set msql alice key
  troclapi:
    key: alice
    format: mysql
    value: secretPassword
  register: alice_trocla
  delegate_to: localhost
  become: false

- name: Show alice mysql cert value
  debug:
    msg: alice_trocla.value
'''


_ansible_ver = float('.'.join(ansible.__version__.split('.')[:2]))

secret = '''$ANSIBLE_VAULT;1.1;AES256
62366137333364653764653438356264336464633930336533636432313562323464656565313732
3130323362356338396539303236356134376439643666650a356134623630366665303435306439
34636365303539626666373161343734666133336361666662363166373630383231313034303938
3031326133396536610a353163393336376638393233313166633738343435316364646532383336
35333164393530393265376339363634336536336663316336613365653737343233306662356238
66313561343164363339306634303164336465346339336332383032366364323430316462396630
33336435323233316139643630373561363238303262626663343236393465653863646439313961
30373630336465383535
'''

NDD = 'troclapi.fr.clara.net'
METHODS = {
    'get': 'GET',
    'create': 'POST',
    'set': 'PUT',
    'reset': 'PATCH',
    'delete': 'DELETE',
    'search': None,
}


def _make_secrets(secret):
    from ansible.constants import DEFAULT_VAULT_ID_MATCH
    from ansible.parsing.vault import VaultSecret

    return [(DEFAULT_VAULT_ID_MATCH, VaultSecret(secret))]


def decrypt(data, script):
    import imp
    from ansible.parsing.vault import VaultLib

    vault_pass = imp.load_source('vault_pass', script)
    password = vault_pass.get_password()

    vault = VaultLib(_make_secrets(password))
    decrypted = vault.decrypt(data)

    return lib_yaml.load(decrypted, Loader=lib_yaml.SafeLoader)


def login(auth, url):
    if auth['vault']:
        a = decrypt(auth['credentials'], auth['vault_pass'])
    else:
        a = auth['credentials']

    # Login
    login = requests.post('{0}/login'.format(url), json=a)
    _login = login.json()

    # Return login result
    if login.status_code != 200 or _login['success'] is False:
        return False, _login, login.cookies
    else:
        return True, _login, login.cookies


def search(url, cookie, key):
    method = 'GET'
    endpoint = '/v1/search/'

    # Run API call
    result = requests.request(
        method,
        url + endpoint + requests.utils.quote(key),
        cookies=cookie,
    )

    if result.status_code == 200:
        if result.json()['success']:
            # If is not Ok
            return True, False, result.json()
        else:
            return False, True, result.json()
    else:
        # If is Ok
        return False, True, result.json()


def default(url, cookie, action, params):
    method = METHODS[action]

    # Check if render
    if method == 'GET' and bool(params['render']):
        render = '/' + params.pop('render')
    else:
        render = ''

    data = {} if method == 'GET' else params.pop('options')

    # Define v1 endpoint
    endpoint = '/v1/key/{0}/{1}{2}'.format(
        requests.utils.quote(params['key']),
        params['format'],
        render
    )

    result = requests.request(
        method,
        url + endpoint,
        cookies=cookie,
        json=data
    )

    if result.status_code != 200 or result.json()['success'] is False:
        return False, True, result.json()
    else:
        return True, False, result.json()


def troclapi(params, cookie):
    url = params['url']
    action = params['action'].lower()

    if action == 'search':
        return search(url, cookie, params['key'])
    else:
        return default(url, cookie, action, params)


def main():
    spec = {
        'auth': {
            'default': {
                'credentials': secret,
                'vault_pass': '/etc/ansible/vault_pass.py',
                'vault': True
            },
            'type': 'dict',
        },
        'url': {
            'default': 'https://' + NDD,
            'type': 'str',
        },
        'action': {
            'default': 'get',
            'type': 'str',
            'choices': METHODS.keys(),
        },
        'key': {
            'default': None,
            'type': 'str',
            'required': True
        },
        'format': {
            'default': 'plain',
            'type': 'str',
        },
        'render': {
            'default': None,
            'type': 'str',
            'choises': ['certonly', 'keyonly'],
        },
        'options': {
            'default': None,
            'type': 'dict',
        },
    }
    module = AnsibleModule(argument_spec=spec)

    l, e, cookie = login(module.params.pop('auth'), module.params['url'])
    if not l:
        module.fail_json(msg='Troclapi connexion failed, see metadata', meta=e)

    change, error, result = troclapi(module.params, cookie)

    if error:
        module.fail_json(msg='Error, see metadata', meta=result)
    else:
        if 'value' in result:
            _v = result['value']
        else:
            _v = result
        module.exit_json(changed=change, value=_v)


if __name__ == '__main__':
    main()
