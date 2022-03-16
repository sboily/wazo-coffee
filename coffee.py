#!/usr/bin/env python3

import logging
import time
from wazo_websocketd_client import Client as Websocket
from wazo_auth_client import Client as Auth
from wazo_calld_client import Client as Calld

from mattermost import MMApi

username = ''
password = ''
wazo_domain = ''
coffee_conference_id = 
domain = ''
channel_id = ''
mm_token = ''
client_id = 'wazo-coffee'

LOG_FORMAT = '%(asctime)s (%(levelname)s) (%(name)s): %(message)s'
logging.basicConfig(format=LOG_FORMAT)


def list_participants():
    return calld.conferences.list_participants(coffee_conference_id)

def parse_participants(participants):
    list_participants = []
    for participant in participants['items']:
        list_participants.append(participant['caller_id_name'])

    if list_participants:
        message = "\n".join(['{} {}'.format("* ", p) for p in list_participants])
        return message

    return None

def notify(handler, message):
    conference_id = handler['data']['conference_id']
    if conference_id == coffee_conference_id:
        participants = parse_participants(list_participants())
        participant = handler['data']['caller_id_name'] or handler['data']['caller_id_number']
        message = message.format(participant)
        props = {
            "override_username": "Coffee machine",
            "override_icon_emoji": True
        }

        if participants:
            props.update({
                "attachments": [{
                    "author_name": "Participants currently present in coffee room",
                    "text": participants,
                }]
            })

        mm.create_post(channel_id, message, props=props)

def conference_joined(handler):
    message = "@here Participant {} has joined the Coffee conference!"
    notify(handler, message)

def conference_left(handler):
    message = "Participant {} has left the Coffee conference!"
    notify(handler, message)

def session_expired(data):
    renew_token()

def get_refresh_token():
    token_data = auth.token.new('wazo_user', access_type='offline', client_id=client_id)
    refresh_token = token_data['refresh_token']
    return token_data['refresh_token']

def get_token():
    token_data = auth.token.new('wazo_user', expiration=3600, refresh_token=refresh_token, client_id=client_id)
    return token_data['token']

def renew_token():
    token_data = auth.token.new('wazo_user', expiration=3600, refresh_token=refresh_token, client_id=client_id)
    token = token_data['token']
    ws.update_token(token)
    calld.set_token(token)

auth = Auth(wazo_domain, username=username, password=password, verify_certificate=False)
refresh_token = get_refresh_token()

calld = Calld(wazo_domain, token=get_token(), verify_certificate=False)
ws = Websocket(wazo_domain, token=get_token(), verify_certificate=False, debug=False)
mm = MMApi("https://{}/api".format(domain))
mm.login(bearer=mm_token)

ws.on('conference_participant_joined', conference_joined)
ws.on('conference_participant_left', conference_left)
ws.on('auth_session_expire_soon', session_expired)

attempts = 0
while True:
    attempts += 1
    if attempts > 1:
        time.sleep(10)
        logging.info('Reconnecting...')
        try:
            renew_token()
        except Exception as e:
            logging.error('Error while renewing token: %s: %s', type(e).__name__, e)
            continue
    try:
        ws.run()
    except Exception as e:
        logging.error('Error while receiving events: %s: %s', type(e).__name__, e)
    except KeyboardInterrupt:
        exit(0)
