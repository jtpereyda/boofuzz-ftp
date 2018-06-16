#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3
from boofuzz import *
#import click


#@click.group()
def cli():
    pass


# @click.command()
# @click.option('--target-host', help='Host or IP address of target', prompt=True)
# @click.option('--target-port', type=int, default=21, help='Network port of target', prompt=True)
# @click.option('--username', help='FTP username', prompt=True)
# @click.option('--password', help='FTP password', prompt=True)
# @click.option('--test-case-index', help='Test case index', type=int)
# @click.option('--test-case-name', help='Name of node or specific test case')
# @click.option('--csv-out', help='Output to CSV file')
# @click.option('--sleep-between-cases', help='Wait time between test cases (floating point)', type=float, default=0)
# @click.option('--procmon-host', help='Process monitor port host or IP')
# @click.option('--procmon-port', type=int, default=26002, help='Process monitor port')
# @click.option('--procmon-start', help='Process monitor start command')
def fuzz():
    target_host = 'localhost'
    target_port = 21
    username = 'anonymous'
    password = 'james'
    test_case_index = None
    test_case_name = None
    csv_out = 'ftp-fuzz.csv'
    sleep_between_cases = 0
    procmon_host = 'localhost'
    procmon_port = 26002
    procmon_start = 'ncat -l 21 -e /bin/cat -k'

    #fuzz_loggers = [FuzzLoggerText()]
    fuzz_loggers = []
    if csv_out is not None:
        f = open(csv_out, 'wb')
        fuzz_loggers.append(FuzzLoggerCsv(file_handle=f))

    if procmon_host is not None:
        procmon = pedrpc.Client(procmon_host, procmon_port)
    else:
        procmon = None

    procmon_options = {}
    if procmon_start is not None:
        procmon_options['start_commands'] = [procmon_start]

    session = Session(
        target=Target(
            connection=SocketConnection(target_host, target_port, proto='tcp'),
            procmon=procmon,
            procmon_options=procmon_options,
        ),
        fuzz_data_logger=FuzzLogger(fuzz_loggers=fuzz_loggers),
        sleep_time=sleep_between_cases
    )

    initialize_ftp(session, username, password)

    if test_case_index is not None:
        session.fuzz_single_case(mutant_index=test_case_index)
    elif test_case_name is not None:
        session.fuzz_by_name(test_case_name)
    else:
        session.fuzz()


def initialize_ftp(session, username, password):
    user = Request(
        'user',
        String(name='key', value='USER'),
        Delim(name='sep', value=' '),
        String(name='value', value=username.encode('ascii')),
        Static(name='end', value='\r\n'),
    )
    password = Request(
        'pass',
        String(name='key', value='PASS'),
        Delim(name='sep', value=' '),
        String(name='value', value=password.encode('ascii')),
        Static(name='end', value='\r\n'),
    )
    stor = Request(
        "stor",
        String(name='key', value='STOR'),
        Delim(name='sep', value=' '),
        String(name='value', value='AAAA'),
        Static(name='end', value='\r\n'),
    )
    retr = Request(
        "retr",
        String(name='key', value='RETR'),
        Delim(name='sep', value=' '),
        String(name='value', value='AAAA'),
        Static(name='end', value='\r\n'),
    )

    session.connect(user)
    session.connect(user, password)
    session.connect(password, stor)
    session.connect(password, retr)


def initialize_ftp_old(session, username, password):
    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string(username.encode('ascii'))
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string(password.encode('ascii'))
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))


#cli.add_command(fuzz)

if __name__ == "__main__":
    fuzz()
