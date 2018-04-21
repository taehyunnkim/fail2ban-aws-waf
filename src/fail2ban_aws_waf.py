#!/usr/bin/env python

import subprocess
import json
import argparse
import logging
import traceback
import os
from time import gmtime, strftime


def exec_command(cmd):
    log_message(logging.INFO, 'Executing command: {}'.format(cmd))

    p = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()

    out = out.encode('ascii', 'ignore')
    err = err.encode('ascii', 'ignore')

    if err is not '':
        raise RuntimeError(err)

    return json.loads(out)


def get_aws_waf_api_name():
    return 'aws waf-regional' if AWS_GLOBAL is False else 'aws waf'


def get_change_token():
    result = exec_command('{} get-change-token'.format(get_aws_waf_api_name()))

    if 'ChangeToken' not in result:
        raise RuntimeError('Could not find ChangeToken in AWS API response')

    return result['ChangeToken']


def create_ip_updates_param(action, ip):
    return json.dumps(
        [{'Action': action.upper(), 'IPSetDescriptor': {'Type': 'IPV4', 'Value': '{}/32'.format(ip)}}],
        separators=(',', ':')
    )


def is_ip_in_ip_sets(ip_set_id, ip):
    result = exec_command('{} get-ip-set --ip-set-id {}'.format(get_aws_waf_api_name(), ip_set_id))

    if 'IPSet' not in result:
        raise RuntimeError('Could not find IPSet in AWS API response')

    if 'IPSetDescriptors' not in result['IPSet']:
        raise RuntimeError('Could not find IPSetDescriptors in AWS API response')

    ips = result['IPSet']['IPSetDescriptors']

    for ip_in_waf in ips:
        if ip_in_waf['Value'] == '{}/32'.format(ip):
            return True

    return False


def update_ip_set(change_token, ip_set_id, action, ip):
    if action == 'INSERT' and is_ip_in_ip_sets(ip_set_id, ip):
        log_message(logging.INFO, 'Attempt to ban IP {}. IP is already in IP set in WAF. Stopping script.'.format(ip))

        return

    if action == 'DELETE' and not is_ip_in_ip_sets(ip_set_id, ip):
        log_message(logging.INFO, 'Attempt to unban IP {}. IP is not in IP set in WAF. Stopping script.'.format(ip))

        return

    result = exec_command("{} update-ip-set {} --change-token {} --ip-set-id {} --updates {}".format(
        get_aws_waf_api_name(),
        '--debug' if AWS_DEBUG is True else '',
        change_token,
        ip_set_id,
        create_ip_updates_param(action, ip)
    ))

    if 'ChangeToken' not in result:
        raise RuntimeError('Could not find ChangeToken in AWS API response')

    return result['ChangeToken']


def parse_cli_args():
    parser = argparse.ArgumentParser(description='Fail2ban AWS WAF auto ban/unban IP script.')

    parser.add_argument(
        '--ip-set-id',
        metavar='AWS GUID',
        type=str,
        required=True,
        help='AWS WAF IP set ID'
    )

    parser.add_argument(
        '--action',
        metavar='ban|unban',
        type=str,
        required=True,
        help='To ban or unban'
    )

    parser.add_argument(
        '--jail-name',
        type=str,
        required=True,
        help='Fail2ban jail name'
    )

    parser.add_argument(
        '--ip',
        metavar='x.x.x.x',
        type=str,
        required=True,
        help='IPv4 to ban/unban'
    )

    parser.add_argument(
        '--logpath',
        metavar='/full/path/to/log/dir',
        type=str,
        help='Absolute path to log directory'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help='Do not run the bot in a loop, but instead execute it just once and exit.'
    )

    parser.add_argument(
        '--global-waf',
        action='store_true',
        default=False,
        help='Defines whether to use waf-regional or waf global API (defaults to regional).'
    )

    return parser.parse_args()


def log_message(level, message):
    AWS_LOGGER.log(level, message)


if __name__ == '__main__':
    args = parse_cli_args()

    AWS_DEBUG = args.debug
    AWS_GLOBAL = args.global_waf
    AWS_LOGPATH = args.logpath

    AWS_LOGGER = logging.getLogger('fail2ban_aws_waf')
    AWS_LOGGER.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s [{}] [%(levelname)s] %(message)s'.format(args.jail_name))
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    AWS_LOGGER.addHandler(stream_handler)

    if AWS_LOGPATH is not None:
        if AWS_LOGPATH[-1:1] == '/':
            AWS_LOGPATH = AWS_LOGPATH[0:-1]

        if not os.path.exists(AWS_LOGPATH):
            raise RuntimeError('Log path {} does not exist.'.format(AWS_LOGPATH))

        file_handler = logging.FileHandler('{}/{}'.format(
            AWS_LOGPATH,
            'fail2ban_aws_waf-{}.log'.format(strftime("%Y%m%d%W", gmtime()))
        ))

        file_handler.setFormatter(formatter)
        AWS_LOGGER.addHandler(file_handler)

    try:
        update_ip_set(
            get_change_token(),
            args.ip_set_id,
            'INSERT' if args.action == 'ban' else 'DELETE',
            args.ip
        )
    except Exception as e:
        log_message(logging.ERROR, 'Exception cought: {}: {}'.format(type(e).__name__, str(e)))
        log_message(logging.ERROR, 'Exception traceback: {}'.format(traceback.format_exc()))

    AWS_LOGGER.removeHandler(stream_handler)
    stream_handler.close()

    if AWS_LOGPATH is not None:
        AWS_LOGGER.removeHandler(file_handler)
        file_handler.close()
