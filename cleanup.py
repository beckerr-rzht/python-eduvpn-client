import sys
from tempfile import mkdtemp
from pathlib import Path
from shutil import rmtree
from typing import Dict, Union
from itertools import chain
import webbrowser
import requests
from requests_oauthlib import OAuth2Session
import gi

gi.require_version('NM', '1.0')
from gi.repository import GLib, NM
from eduvpn.oauth2 import one_request, get_open_port
from eduvpn.crypto import gen_code_challenge, gen_code_verifier, common_name_from_cert

INSTITUTES_URI = "https://static.eduvpn.nl/disco/institute_access.json"
DISCO_URI = 'https://disco.eduvpn.org/'
ORGANISATION_URI = DISCO_URI + "organization_list_2.json"
CLIENT_ID = "org.eduvpn.app.linux"
SCOPE = ["config"]
CODE_CHALLENGE_METHOD = "S256"
LANGUAGE = 'nl'
COUNTRY = "nl-NL"


def list_orgs():
    org_list_url = ORGANISATION_URI
    org_list_response = requests.get(org_list_url)
    organization_list = org_list_response.json()['organization_list']
    return organization_list


def extract_translation(d: Union[str, Dict[str, str]]):
    if type(d) != dict:
        return d
    for m in [COUNTRY, LANGUAGE, 'en-US', 'en']:
        try:
            return d[m]
        except KeyError:
            continue
    return list(d.values())[0]  # otherwise just return first in list


def get_info(base_uri: str):
    info_url = base_uri + 'info.json'
    info = requests.get(info_url).json()['api']['http://eduvpn.org/api#2']
    api_base_uri = info['api_base_uri']
    token_endpoint = info['token_endpoint']
    auth_endpoint = info['authorization_endpoint']
    return api_base_uri, token_endpoint, auth_endpoint


def get_config(oauth, api_base_uri, profile_id):
    response = oauth.get(api_base_uri + f'/profile_config?profile_id={profile_id}')
    return response.text


def list_profiles(oauth, api_base_uri):
    profile_list_response = oauth.get(api_base_uri + '/profile_list')
    return profile_list_response.json()['profile_list']['data']


def create_keypair(oauth: OAuth2Session, api_base_uri: str) -> (str, str):
    response = oauth.post(api_base_uri + '/create_keypair')
    keypair = response.json()['create_keypair']['data']
    private_key = keypair['private_key']
    certificate = keypair['certificate']
    return private_key, certificate


def system_messages(oauth: OAuth2Session, api_base_uri: str):
    response = oauth.get(api_base_uri + '/system_messages')
    return response.json()['system_messages']['data']


def check_certificate(oauth: OAuth2Session, api_base_uri: str, certificate: str):
    common_name = common_name_from_cert(certificate.encode('ascii'))
    response = oauth.get(api_base_uri + '/check_certificate?common_name=' + common_name)
    return response.json()['check_certificate']['data']['is_valid']


def get_oauth(token_endpoint: str, authorization_endpoint: str):
    port = get_open_port()
    redirect_uri = f'http://127.0.0.1:{port}/callback'
    oauth = OAuth2Session(CLIENT_ID, redirect_uri=redirect_uri, auto_refresh_url=token_endpoint, scope=SCOPE)

    code_verifier = gen_code_verifier()
    code_challenge = gen_code_challenge(code_verifier)
    authorization_url, state = oauth.authorization_url(url=authorization_endpoint,
                                                       code_challenge_method=CODE_CHALLENGE_METHOD,
                                                       code_challenge=code_challenge)

    webbrowser.open(authorization_url)
    response = one_request(port, lets_connect=False)
    code = response['code'][0]
    assert (state == response['state'][0])
    token = oauth.fetch_token(token_url=token_endpoint, code=code, code_verifier=code_verifier,
                              client_id=oauth.client_id, include_client_id=True)
    return oauth


def list_institutes():
    institute_access_response = requests.get(INSTITUTES_URI)
    institute_access_list = institute_access_response.json()['instances']
    return institute_access_list


def menu() -> str:
    """
    Print options, returns target URL on success, exits client with error code 1 on failure.
    """
    if len(sys.argv) == 1:
        print("# Institute access \n")
        for i, row in enumerate(list_institutes()):
            print(f"[{i}] {extract_translation(row['display_name'])}")

        print("# Secure internet \n")

        for i, row in enumerate(list_orgs()):
            print(f"[{i}] {extract_translation(row['display_name'])}")
        sys.exit(1)

    if len(sys.argv) == 2:
        search = sys.argv[1].lower()

        institute_match = [i for i in list_institutes() if search in extract_translation(i['display_name']).lower()]

        org_match = [i for i in list_orgs() if search in i['display_name'] or
                     ('keyword_list' in i and search in i['keyword_list'])]

        if len(institute_match) == 0 and len(org_match) == 0:
            print(f"The filter '{search}' had no matches")
            sys.exit(1)
        elif len(institute_match) == 1 and len(org_match) == 0:
            institute = institute_match[0]
            print(f"filter {search} matched with institute '{institute['display_name']}'")
            return institute['base_uri']
        elif len(institute_match) == 0 and len(org_match) == 1:
            org = org_match[0]
            print(f"filter {search} matched with organisation '{org['display_name']}'")
        else:
            matches = [i['display_name'] for i in chain(institute_match, org_match)]
            print(f"filter '{search}' matched with {len(matches)} organisations, please be more specific.")
            print("Matches:")
            [print(f" - {extract_translation(m)}") for m in matches]
            sys.exit(1)


def write_config(config: str):
    with open('eduvpn.ovpn', mode='w+t') as f:
        f.writelines(config)


def ovpn_import(target: Path):
    for vpn_info in NM.VpnPluginInfo.list_load():
        try:
            return vpn_info.load_editor_plugin().import_(str(target))
        except Exception as e:
            print(f"can't import config: {e}")


def import_config(config: str, private_key: str, certificate: str):
    target_parent = Path(mkdtemp())
    target = target_parent / "eduVPN.ovpn"

    with open(target, mode='w+t') as f:
        f.writelines(config)
        f.writelines(f"\n<key>\n{private_key}\n</key>\n")
        f.writelines(f"\n<cert>\n{certificate}\n</cert>\n")

    connection = ovpn_import(target)
    connection.normalize()
    client = NM.Client.new(None)
    main_loop = GLib.MainLoop()

    def added_cb(client, result, _):
        try:
            client.add_connection_finish(result)
            print("The connection profile has been successfully added to NetworkManager.")
        except Exception as e:
            print("ERROR: failed to add connection: %s\n" % e)
        main_loop.quit()

    client.add_connection_async(connection, True, None, added_cb, None)
    main_loop.run()
    rmtree(target_parent)


def main():
    url = menu()
    api_base_uri, token_endpoint, auth_endpoint = get_info(url)
    oauth = get_oauth(token_endpoint, auth_endpoint)
    profile_id = list_profiles(oauth, api_base_uri)[0]['profile_id']
    config = get_config(oauth, api_base_uri, profile_id)
    private_key, certificate = create_keypair(oauth, api_base_uri)
    import_config(config, private_key, certificate)


if __name__ == '__main__':
    main()
