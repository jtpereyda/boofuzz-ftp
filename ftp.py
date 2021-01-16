#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3
import re

from boofuzz import *
from boofuzz.constants import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.process_monitor_local import ProcessMonitorLocal
import click


class BooFtpException(Exception):
    pass


def check_reply_code(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """
        Args:
            target (Target): Target with sock-like interface.
            fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
                Provided with a test case and test step already opened.
            session (Session): Session object calling post_send.
                Useful properties include last_send and last_recv.
            test_case_context (ProtocolSession): Context for test case-scoped data.
                :py:class:`TestCaseContext` :py:attr:`session_variables <TestCaseContext.session_variables>`
                values are generally set within a callback and referenced in elements via default values of type
                :py:class:`ReferenceValueTestCaseSession`.
            args: Implementations should include \\*args and \\**kwargs for forward-compatibility.
            kwargs: Implementations should include \\*args and \\**kwargs for forward-compatibility.
    """
    if test_case_context.previous_message.name == "__ROOT_NODE__":
        return
    else:
        try:
            fuzz_data_logger.log_info("Parsing reply contents: {0}".format(session.last_recv))
            parse_ftp_reply(session.last_recv)
        except BooFtpException as e:
            fuzz_data_logger.log_fail(str(e))
        fuzz_data_logger.log_pass()


def parse_ftp_reply(data):
    """
    Parse FTP reply and return reply code. Raise BooFtpException if reply is invalid.

    Note:
    1. Multi-line replies not supported yet
    
    RFC 959 excerpt:
          A reply is defined to contain the 3-digit code, followed by Space
          <SP>, followed by one line of text (where some maximum line length
          has been specified), and terminated by the Telnet end-of-line
          code.  There will be cases however, where the text is longer than
          a single line...

    Args:
        data (bytes): Raw reply data
    """
    reply_code_len = 3
    if len(data) < reply_code_len:
        raise BooFtpException("Invalid FTP reply, too short; must be a 3-digit sequence followed by a space")
    else:
        try:
            reply = data[0:reply_code_len+1].decode('ascii')
        except ValueError:
            raise BooFtpException("Invalid FTP reply, non-ASCII characters; must be a 3-digit sequence followed by a space")
        if not re.match('[1-5][0-9][0-9] ', reply[0:4]):
            raise BooFtpException("Invalid FTP reply; must be a 3-digit sequence followed by a space")
        else:
            return reply[0:reply_code_len]


@click.group()
def cli():
    pass


@click.command()
@click.option('--target-host', help='Host or IP address of target', prompt=True)
@click.option('--target-port', type=int, default=21, help='Network port of target')
@click.option('--username', help='FTP username', prompt=True)
@click.option('--password', help='FTP password', prompt=True)
@click.option('--test-case-index', help='Test case index', type=int)
@click.option('--test-case-name', help='Name of node or specific test case')
@click.option('--csv-out', help='Output to CSV file')
@click.option('--sleep-between-cases', help='Wait time between test cases (floating point)', type=float, default=0)
@click.option('--procmon-host', help='Process monitor port host or IP')
@click.option('--procmon-port', type=int, default=DEFAULT_PROCMON_PORT, help='Process monitor port')
@click.option('--procmon-start', help='Process monitor start command')
@click.option('--procmon-capture', is_flag=True, help='Capture stdout/stderr from target process upon failure')
@click.option('--tui/--no-tui', help='Enable/disable TUI')
@click.option('--text-dump/--no-text-dump', help='Enable/disable full text dump of logs', default=False)
@click.option('--feature-check', is_flag=True, help='Run a feature check instead of a fuzz test', default=False)
@click.argument('target_cmdline', nargs=-1, type=click.UNPROCESSED)
def fuzz(target_cmdline, target_host, target_port, username, password,
         test_case_index, test_case_name, csv_out, sleep_between_cases,
         procmon_host, procmon_port, procmon_start, procmon_capture, tui, text_dump, feature_check):
    local_procmon = None
    if len(target_cmdline) > 0 and procmon_host is None:
        local_procmon = ProcessMonitorLocal(crash_filename="boofuzz-crash-bin",
                                            proc_name=None,  # "proftpd",
                                            pid_to_ignore=None,
                                            debugger_class=DebuggerThreadSimple,
                                            level=1)

    fuzz_loggers = []
    if text_dump:
        fuzz_loggers.append(FuzzLoggerText())
    elif tui:
        fuzz_loggers.append(FuzzLoggerCurses())
    if csv_out is not None:
        f = open('ftp-fuzz.csv', 'wb')
        fuzz_loggers.append(FuzzLoggerCsv(file_handle=f))

    procmon_options = {}
    if procmon_start is not None:
        procmon_options['start_commands'] = [procmon_start]
    if target_cmdline is not None:
        procmon_options['start_commands'] = [list(target_cmdline)]
    if procmon_capture:
        procmon_options['capture_output'] = True

    if local_procmon is not None or procmon_host is not None:
        if procmon_host is not None:
            procmon = ProcessMonitor(procmon_host, procmon_port)
        else:
            procmon = local_procmon
        procmon.set_options(**procmon_options)
        monitors = [procmon]
    else:
        procmon = None
        monitors = []

    start = None
    end = None
    fuzz_only_one_case = None
    if test_case_index is None:
        start = 1
    elif "-" in test_case_index:
        start, end = test_case_index.split("-")
        if not start:
            start = 1
        else:
            start = int(start)
        if not end:
            end = None
        else:
            end = int(end)
    else:
        fuzz_only_one_case = int(test_case_index)

    connection = TCPSocketConnection(target_host, target_port)

    session = Session(
        target=Target(
            connection=connection,
            monitors=monitors,
        ),
        fuzz_loggers=fuzz_loggers,
        sleep_time=sleep_between_cases,
        index_start=start,
        index_end=end,
    )

    initialize_ftp(session, username, password)

    if feature_check:
        session.feature_check()
    elif fuzz_only_one_case is not None:
        session.fuzz_single_case(mutant_index=fuzz_only_one_case)
    elif test_case_name is not None:
        session.fuzz_by_name(test_case_name)
    else:
        session.fuzz()

    if procmon is not None:
        procmon.stop_target()


def initialize_ftp(session, username, password):
    """
    RFC 5797:


    2.4.  Base FTP Commands

       The following commands are part of the base FTP specification
       [RFC0959] and are listed in the registry with the immutable pseudo
       FEAT code "base".

	  Mandatory commands:

	  ABOR, ACCT, ALLO, APPE, CWD, DELE, HELP, LIST, MODE, NLST, NOOP,
	  PASS, PASV, PORT, QUIT, REIN, REST, RETR, RNFR, RNTO, SITE, STAT,
	  STOR, STRU, TYPE, USER

    """
    user = _ftp_cmd_1_arg(cmd_code="USER", default_value=username.encode('ascii'))
    password = _ftp_cmd_1_arg(cmd_code="PASS", default_value=password.encode('ascii'))
    stor = _ftp_cmd_1_arg(cmd_code="STOR", default_value="AAAA")
    retr = _ftp_cmd_1_arg(cmd_code="RETR", default_value="AAAA")
    mkd = _ftp_cmd_1_arg(cmd_code="MKD", default_value="AAAA")
    abor = _ftp_cmd_0_arg(cmd_code="ABOR")

    session.connect(user, callback=check_reply_code)
    session.connect(user, password, callback=check_reply_code)
    session.connect(password, stor, callback=check_reply_code)
    session.connect(password, retr, callback=check_reply_code)
    session.connect(password, mkd, callback=check_reply_code)
    session.connect(password, abor, callback=check_reply_code)
    session.connect(stor, abor, callback=check_reply_code)
    session.connect(retr, abor, callback=check_reply_code)
    session.connect(mkd, abor, callback=check_reply_code)


def _ftp_cmd_0_arg(cmd_code):
    return Request(
        cmd_code.lower(),
        children=(
            String(name='key', default_value=cmd_code),
            Static(name='end', default_value='\r\n'),
        ),
    )


def _ftp_cmd_1_arg(cmd_code, default_value):
    return Request(
        cmd_code.lower(),
        children=(
            String(name='key', default_value=cmd_code),
            Delim(name='sep', default_value=' '),
            String(name='value', default_value=default_value),
            Static(name='end', default_value='\r\n'),
        ),
    )


cli.add_command(fuzz)

if __name__ == "__main__":
    cli()
