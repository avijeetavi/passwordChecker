import hashlib

import requests

import  sys


def request_api_data(query_char):
    '''
    Tihs funciton will query to pwnedpasswords with query_char and get all the matching password in response
    :param query_char:  first five digit of hashed password
    :return: return all the response got in query
    '''
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetch: {res.status_code}')

    return res


def get_password_leak_count(hashes, hash_to_check):
    '''
    If password is matched then reutrn the number of count
    :param hashes: all hashes text came in response of request_api_data
    :param hash_to_check: hashed password after fifth index to last
    :return:
    '''
    hash = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hash:
        if h == hash_to_check:
            return True, count

    return False, 0


def hash_password(actual_password):
    '''
        Convert the raw password in Sha1 hash
    :param actual_password: raw password taken from user
    :return: fir_5Char in sha1 hashed format and tail_char as all other sha1 hashed password after 5th digit
    '''
    sha1password = hashlib.sha1(actual_password.encode('utf-8')).hexdigest().upper()
    first_5Char, tail_char = sha1password[:5], sha1password[5:]
    return first_5Char, tail_char


def main():
    pas = input('Enter a password: ')
    first_5char, tail_char = hash_password(pas)
    response = request_api_data(first_5char)
    rt, count = get_password_leak_count(response, tail_char)
    if rt:
        print(f'{pas}: is hacked: {count} times')
    else:
        print(f'password: "{pas}" is never hacked')

    return "Execution Completes"

if __name__ == '__main__':
    sys.exit(main())
