#!/usr/bin/env python3
import argparse
import time
import multiprocessing
import json
import sys
import textwrap
import threading

from functools import partial
from datetime import datetime, timedelta

import requests
import google.oauth2.credentials
from tqdm import tqdm

from google.cloud import storage
from google.oauth2 import service_account


def outprint(data='', file_path='', normal_print=''):
    with open(file_path, 'a+') as f:
        f.write('{}\n'.format(data))
    normal_print(data)

def generate_bucket_permutations(keyword):
    permutation_templates = [
        '{keyword}-{permutation}',
        '{permutation}-{keyword}',
        '{keyword}_{permutation}',
        '{permutation}_{keyword}',
        '{keyword}{permutation}',
        '{permutation}{keyword}'
    ]
    with open('./permutations.txt', 'r') as f:
        permutations = f.readlines()
        buckets = []
        for perm in permutations:
            perm = perm.rstrip()
            for template in permutation_templates:
                generated_string = template.replace('{keyword}', keyword).replace('{permutation}', perm)
                buckets.append(generated_string)

    buckets.append(keyword)
    buckets.append('{}.com'.format(keyword))
    buckets.append('{}.net'.format(keyword))
    buckets.append('{}.org'.format(keyword))
    buckets = list(set(buckets))

    buckets = [b for b in buckets if 3 <= len(b) <= 63]

    print('\nGenerated {} bucket permutations.\n'.format(len(buckets)))
    return buckets

def read_wordlist(filename):
    try:
        file = open(filename, 'r')
        lines = file.read().splitlines()
        file.close()
        return lines
    except FileNotFoundError:
        print('Error: File not found')
        exit(1)
    except PermissionError:
        print('Error: Permission denied')
        exit(1)

def main(args):
    if args.out_file:
        global print
        normal_print = print
        print = partial(outprint, file_path=args.out_file, normal_print=normal_print)

    if args.unauthenticated:
        client = None
    elif args.service_account_credential_file_path:
        credentials = service_account.Credentials.from_service_account_file(args.service_account_credential_file_path)
        client = storage.Client(project=None, credentials=credentials)
    else:
        use_access_token = input('No credential file passed in, enter an access token to authenticate? (y/n) ')
        if use_access_token.rstrip().lower() == 'y':
            access_token = input('Enter an access token to use for authentication: ')
            credentials = google.oauth2.credentials.Credentials(access_token.rstrip())
            client = storage.Client(project=None, credentials=credentials)
        else:
            default = input('No credential file passed in and no access token entered, use the default credentials? (y/n) ')
            if default.rstrip().lower() == 'y':
                client = storage.Client(project=None)
            else:
                print('\nNo authentication method selected. Only performing unauthenticated enumeration.')
                client = None

    if args.keyword:
        buckets = generate_bucket_permutations(args.keyword)
    elif args.wordlist:
        buckets = read_wordlist(args.wordlist)
    elif args.check:
        buckets = args.check
    elif args.check_list:
        with sys.stdin if args.check_list == '-' else open(args.check_list, 'r') as fd:
            buckets = fd.read().splitlines()

    start_time = time.time()
    counter = multiprocessing.Value('i', 0)

    def show_progress():
        with tqdm(total=len(buckets), desc='Scanning Buckets') as pbar:
            last = 0
            while True:
                with counter.get_lock():
                    current = counter.value
                pbar.update(current - last)
                last = current
                if current >= len(buckets):
                    break
                time.sleep(0.1)

    progress_thread = threading.Thread(target=show_progress)
    progress_thread.start()

    subprocesses = []
    for i in range(0, args.subprocesses):
        start = int(len(buckets) / args.subprocesses * i)
        end = int(len(buckets) / args.subprocesses * (i+1))
        permutation_list = buckets[start:end]
        subproc = Worker(client, print, permutation_list, args.out_file, counter)
        subprocesses.append(subproc)
        subproc.start()

    cancelled = False
    try:
        for s in subprocesses:
            s.join()
    except KeyboardInterrupt:
        cancelled = True
        print('Ctrl+C pressed, killing subprocesses...')

    progress_thread.join()

    if not cancelled:
        end_time = time.time()
        scanning_duration = timedelta(seconds=(end_time - start_time))
        d = datetime(1, 1, 1) + scanning_duration

        if d.day - 1 > 0:
            print('\nScanned {} potential buckets in {} day(s), {} hour(s), {} minute(s), and {} second(s).'.format(len(buckets), d.day-1, d.hour, d.minute, d.second))
        elif d.hour > 0:
            print('\nScanned {} potential buckets in {} hour(s), {} minute(s), and {} second(s).'.format(len(buckets), d.hour, d.minute, d.second))
        elif d.minute > 0:
            print('\nScanned {} potential buckets in {} minute(s) and {} second(s).'.format(len(buckets), d.minute, d.second))
        else:
            print('\nScanned {} potential buckets in {} second(s).'.format(len(buckets), d.second))

    print('\nGracefully exiting!')
    if args.out_file:
        print = normal_print

class Worker(multiprocessing.Process):
    def __init__(self, client, print, permutation_list, out_file, counter):
        super().__init__()
        self.client = client
        self.print = print
        self.permutation_list = permutation_list
        self.out_file = out_file
        self.counter = counter

    def run(self):
        try:
            for bucket_name in self.permutation_list:
                if self.check_existence(bucket_name):
                    self.check_permissions(bucket_name)
                with self.counter.get_lock():
                    self.counter.value += 1
        except KeyboardInterrupt:
            return

    def check_existence(self, bucket_name):
        response = requests.head('https://www.googleapis.com/storage/v1/b/{}'.format(bucket_name))
        return response.status_code not in [400, 404]

    def check_permissions(self, bucket_name):
        authenticated_permissions = []
        unauthenticated_permissions = []

        if self.client:
            authenticated_permissions = self.client.bucket(bucket_name).test_iam_permissions(
                permissions=[
                    'storage.buckets.delete',
                    'storage.buckets.get',
                    'storage.buckets.getIamPolicy',
                    'storage.buckets.setIamPolicy',
                    'storage.buckets.update',
                    'storage.objects.create',
                    'storage.objects.delete',
                    'storage.objects.get',
                    'storage.objects.list',
                    'storage.objects.update'
                ]
            )
            if authenticated_permissions:
                self.print('\n    AUTHENTICATED ACCESS ALLOWED: {}'.format(bucket_name))
                if 'storage.buckets.setIamPolicy' in authenticated_permissions:
                    self.print('        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)')
                if 'storage.objects.list' in authenticated_permissions:
                    self.print('        - AUTHENTICATED LISTABLE (storage.objects.list)')
                if 'storage.objects.get' in authenticated_permissions:
                    self.print('        - AUTHENTICATED READABLE (storage.objects.get)')
                if any(p in authenticated_permissions for p in ['storage.objects.create', 'storage.objects.delete', 'storage.objects.update']):
                    self.print('        - AUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)')
                self.print('        - ALL PERMISSIONS:')
                self.print(textwrap.indent('{}\n'.format(json.dumps(authenticated_permissions, indent=4)), '        '))

        unauthenticated_permissions = requests.get(
            'https://www.googleapis.com/storage/v1/b/{}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update'.format(bucket_name)
        ).json()

        if unauthenticated_permissions.get('permissions'):
            self.print('\n    UNAUTHENTICATED ACCESS ALLOWED: {}'.format(bucket_name))
            if 'storage.buckets.setIamPolicy' in unauthenticated_permissions['permissions']:
                self.print('        - VULNERABLE TO PRIVILEGE ESCALATION (storage.buckets.setIamPolicy)')
            if 'storage.objects.list' in unauthenticated_permissions['permissions']:
                self.print('        - UNAUTHENTICATED LISTABLE (storage.objects.list)')
            if 'storage.objects.get' in unauthenticated_permissions['permissions']:
                self.print('        - UNAUTHENTICATED READABLE (storage.objects.get)')
            if any(p in unauthenticated_permissions['permissions'] for p in ['storage.objects.create', 'storage.objects.delete', 'storage.objects.update']):
                self.print('        - UNAUTHENTICATED WRITABLE (storage.objects.create, storage.objects.delete, and/or storage.objects.update)')
            self.print('        - ALL PERMISSIONS:')
            self.print(textwrap.indent('{}\n'.format(json.dumps(unauthenticated_permissions['permissions'], indent=4)), '            '))

        if not (authenticated_permissions or unauthenticated_permissions.get('permissions')):
            self.print('    EXISTS: {}'.format(bucket_name))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script will generate a list of permutations from ./permutations.txt using the keyword passed into the -k/--keyword argument. Then it will attempt to enumerate Google Storage buckets with those names without any authentication. If a bucket is found to be listable, it will be reported (buckets that allow access to "allUsers"). If a bucket is found but it is not listable, it will use the default "gcloud" CLI credentials to try and list the bucket. If the bucket is listable with credentials it will be reported (buckets that allow access to "allAuthenticatedUsers"), otherwise it will reported as existing, but unlistable.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', required=False, action="append", help='Check a single bucket name instead of bruteforcing names based on a keyword. May be repeated to check multiple buckets.')
    group.add_argument('--check-list', required=False, default=None, help='Check a list of buckets in the given file, one per line.')
    group.add_argument('-k', '--keyword', required=False, help='The base keyword to use when guessing bucket names.')
    group.add_argument('-w', '--wordlist', required=False, default=None, help='The path to a wordlist file')
    parser.add_argument('-s', '--subprocesses', required=False, default=5, type=int, help='The amount of subprocesses to delegate work to for enumeration. Default: 5.')
    parser.add_argument('-f', '--service-account-credential-file-path', required=False, default=None, help='The path to the JSON file that contains the private key for a GCP service account.')
    parser.add_argument('-u', '--unauthenticated', required=False, default=False, action='store_true', help='Force an unauthenticated scan')
    parser.add_argument('-o', '--out-file', required=False, default=None, help='The path to a log file to write the scan results to.')
    args = parser.parse_args()

    main(args)
