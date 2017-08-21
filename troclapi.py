#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import requests
from ansible.parsing.dataloader import DataLoader
from ansible.module_utils.basic import *  # noqa: F403

DOCUMENTATION = '''
module: trolcapi
short_description: "Troclapi usage for Ansible"
description:
    - "Ansible module for connect to troclapi. Please see api documentation for more informations https://github.com/fe80/troclapi"
author: Fe80
options:
  token:
    description: admin troclapi token
    default: { 'token': secret, 'vautl_pass': '/etc/ansible/vault_pass.py', 'vault': True } secret variable is define on module script
    required: false
    type: dict
  url:
    description: troclapi url
    default: https:// + ndd variable on module script
    required: false
    type: str
  action:
    description: trocla action
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
    description: trocla key name
    default: None
    required: true
    type: str
  format:
    description: trocla format key
    default: plain
    required: false
    type: str
  render:
    description: render option for get value
    choices:
      - certonly
      - keyonly
    default: None
    required: false
    type: str
  options:
    description: trocla options, see api documentation for more information
    type: dict
    required: false
    default: {}
'''

EXAMPLES = '''
- name: Get trocla plain value for key toto
  troclapi:
    key: toto
  register: toto_trocla

- name: Show toto key value
  debug:
    msg: toto_trocla.value

- name: Get trocla x509 cert value for key bob
  troclapi:
    key: bob
    render: certonly
  register: bob_trocla

- name: Show bob x509 cert value
  debug:
    msg: bob_trocla.value

- name: Set msql alice key
  troclapi:
    key: alice
    format: mysql
    value: secretPassword
  register: alice_trocla

- name: Show alice mysql cert value
  debug:
    msg: alice_trocla.value
'''

secret = '''$ANSIBLE_VAULT;1.1;AES256
32396232373930313037643031376265643665313365333432393561393465323964616133343638
6438343738663336666361343030636631336135613066650a346530626366663463356562636233
61663261656534373862663737303437653734333734643864363961383062623338336133383330
6364333838326137610a656265373261323232383664376166643336663865363333663836356138
38383831633732666434613561653635323461633365366234366239313930333035
'''
ndd = 'troclapi.puppet'
methods = {
    'get': 'GET',
    'create': 'POST',
    'set': 'PUT',
    'reset': 'PATCH',
    'delete': 'DELETE',
}


def uncrypted(data, script):
    import imp
    from ansible.parsing.vault import VaultLib

    vault_pass = imp.load_source('vault_pass', script)
    password = vault_pass.get_password()

    vault = VaultLib(password)
    uncrypt = vault.decrypt(data)

    loader = DataLoader()
    result = loader.load(data=uncrypt)

    return result


def login(auth, url):
    a = uncrypted(auth['credentials'], auth['vault_pass']) if auth['vault'] else auth['credentials']

    # Login
    login = requests.post('{0}/login'.format(url), json=a)
    l = login.json()

    # Return login result
    if login.status_code is not 200 or l['success'] is False:
        return False, l, login.cookies
    else:
        return True, l, login.cookies


def troclapi(params, methods, cookie):
    method = methods[params['action'].lower()]
    url = params['url']

    # Check if render
    render = '/' + params.pop('render') if method is 'GET' and params['render'] else ''

    # Remove options for get method
    options = {} if method is 'GET' else params.pop('options')

    # Define v1 endpoint
    endpoint = '/v1/key/{0}/{1}{2}'.format(params['key'], params['format'], render)

    # Run API call
    result = requests.request(method, url + endpoint, cookies=cookie, json=options)
    r = result.json()

    if result.status_code is not 200 or r['success'] is False:
        # If is not Ok
        return False, True, r
    else:
        # If is Ok
        return True, False, r


def main():
    spec = {
        'auth': {
            'default': {'credentials': secret, 'vault_pass': '/etc/ansible/vault_pass.py', 'vault': True},
            'type': 'dict',
        },
        'url': {
            'default': 'https://' + ndd,
            'type': 'str',
        },
        'action': {
            'default': 'get',
            'type': 'str',
            'choices': methods.keys(),
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
    module = AnsibleModule(argument_spec=spec)  # noqa: F405

    l, e, cookie = login(module.params.pop('auth'), module.params['url'])
    if not l:
        module.fail_json(msg='Troclapi connexion failed, see metadata', meta=e)

    change, error, result = troclapi(module.params, methods, cookie)

    if error:
        module.fail_json(msg='Error, see metadata', meta=result)
    else:
        module.exit_json(changed=change, value=result['value'])


if __name__ == '__main__':
    main()
