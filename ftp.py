#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3
import logging
import re
import time

import click
from boofuzz import *

ftp_reply_regex = re.compile('[2345][0-9][0-9]')


@click.group()
def cli():
    pass


@click.command()
@click.option('--target-host', help='Host or IP address of target', prompt=True)
@click.option('--target-port', type=int, default=21, help='Network port of target (default 21)')
@click.option('--username', help='FTP username', prompt=True)
@click.option('--password', help='FTP password', prompt=True)
@click.option('--test-case-index', help='Test case index', type=int)
@click.option('--test-case-name', help='Name of node or specific test case')
@click.option('--csv-out', help='Output to CSV file')
@click.option('--sleep-between-cases', help='Wait time between test cases (floating point)', type=float, default=0)
@click.option('--procmon', help='Enable procmon (process monitor) on same host as --target-host', is_flag=True)
@click.option('--procmon-host', help='Enable procmon (process monitor) on specified host or IP')
@click.option('--procmon-port', type=int, default=26002, help='Process monitor port')
@click.option('--procmon-start',
              help='Process monitor start command (may be used repeatedly to specify multiple commands', multiple=True)
@click.option('--procmon-stop',
              help='Process monitor stop command (may be used repeatedly to specify multiple commands', multiple=True)
@click.option('--skip', help='Skip n test cases (default 0)', type=int, default=0)
@click.option('--quiet', '-q', help='Quieter output', is_flag=True)
@click.option('--debug', help='Print debug info to console', is_flag=True)
@click.option('--feature-check', help='Check supported protocol features instead of fuzzing', is_flag=True)
@click.option('--fail-on-no-reply/--pass-on-no-reply', help='Treat no reply as failure. Disabled by default.', default=False)
def fuzz(target_host, target_port, username, password, test_case_index, test_case_name, csv_out, sleep_between_cases,
         procmon, procmon_host, procmon_port, procmon_start, procmon_stop, skip, quiet, debug, feature_check, fail_on_no_reply):
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    fuzz_loggers = []

    if not quiet:
        fuzz_loggers.append(FuzzLoggerText())

    if csv_out is not None:
        f = open('ftp-fuzz.csv', 'wb')
        fuzz_loggers.append(FuzzLoggerCsv(file_handle=f))

    if procmon or procmon_host is not None:
        if procmon_host is None:
            procmon_host = target_host

        procmon_ref = pedrpc.Client(procmon_host, procmon_port)

        procmon_options = {'start_commands': procmon_start,
                           'stop_commands': procmon_stop, }
    else:
        procmon_ref = None
        procmon_options = None

    session = Session(
        target=Target(
            connection=SocketConnection(target_host, target_port, proto='tcp'),
            procmon=procmon_ref,
            procmon_options=procmon_options,
        ),
        fuzz_loggers=fuzz_loggers,
        sleep_time=sleep_between_cases,
        skip=skip,
        check_data_received_each_request=fail_on_no_reply,
    )

    initialize_ftp(session, username, password)

    if feature_check:
        session.feature_check()
    else:
        if test_case_index is not None:
            session.fuzz_single_case(mutant_index=test_case_index)
        elif test_case_name is not None:
            session.fuzz_by_name(test_case_name)
        else:
            session.fuzz()

    print('Test complete. Serving web page. Hit Ctrl+C to quit.')
    while True:
        time.sleep(.001)


def ftp_check(target, fuzz_data_logger, session, sock, *args, **kwargs):
    """
    Overload or replace this routine to specify actions to run after to each fuzz request. The order of events is
    as follows::

        pre_send() - req - callback ... req - callback - post_send()

    Potential uses:
     * Closing down a connection.
     * Checking for expected responses.

    @see: pre_send()

    Args:
        target (Target): Target with sock-like interface.
        fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
            Provided with a test case and test step already opened.

        session (Session): Session object calling post_send.
            Useful properties include last_send and last_recv.

        sock: DEPRECATED Included for backward-compatibility. Same as target.
        args: Implementations should include \*args and \**kwargs for forward-compatibility.
        kwargs: Implementations should include \*args and \**kwargs for forward-compatibility.
    """
    target.close()
    target.open()
    target.send('USER {0}\r\n'.format('admin'))
    reply = target.recv(10000)
    fuzz_data_logger.log_check('Checking reply matches regex /{0}/'.format(ftp_reply_regex.pattern))
    if re.match(ftp_reply_regex, reply):
        # TODO This tends to match the banner received instead of the USER reply.
        # Solution: Utilize the Session's feature_check functionality instead of manually reproducing here
        fuzz_data_logger.log_pass('Match')
    else:
        fuzz_data_logger.log_fail('No match')


def recv_banner(target, fuzz_data_logger, session, *args, **kwargs):
    banner = target.recv(10000)
    fuzz_data_logger.log_check('Checking banner matches regex /{0}/'.format(ftp_reply_regex.pattern))
    if re.match(ftp_reply_regex, banner):
        fuzz_data_logger.log_pass('Match')
    else:
        fuzz_data_logger.log_fail('No match')


def initialize_ftp(session, username, password):
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

    s_initialize("appe")
    s_string("APPE")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("allo-no-page-size")
    s_string("ALLO")
    s_delim(" ")
    s_qword(7, output_format='ascii', name='num_bytes')
    s_static("\r\n")

    s_initialize("allo-with-page-size")
    s_string("ALLO")
    s_delim(" ")
    s_qword(7, output_format='ascii', name='num_bytes')
    s_delim(" R ")
    s_qword(9, output_format='ascii', name='page_size')
    s_static("\r\n")

    session.connect(s_get("user"), callback=recv_banner)
    session.connect(s_get("user"), s_get("pass"))

    session.connect(s_get("pass"), s_get("allo-no-page-size"))
    session.connect(s_get("pass"), s_get("allo-with-page-size"))

    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("allo-no-page-size"), s_get("stor"))
    session.connect(s_get("allo-with-page-size"), s_get("stor"))

    session.connect(s_get("pass"), s_get("appe"))
    session.connect(s_get("allo-no-page-size"), s_get("appe"))
    session.connect(s_get("allo-with-page-size"), s_get("appe"))

    session.connect(s_get("pass"), s_get("retr"))

    session.post_send = ftp_check


cli.add_command(fuzz)

if __name__ == "__main__":
    cli()
