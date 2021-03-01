#!/usr/bin/env python
# Designed for use with boofuzz v0.3.0 branch cli-main
import re

from boofuzz import *
import boofuzz
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
            reply = data[0:reply_code_len + 1].decode('ascii')
        except ValueError:
            raise BooFtpException(
                "Invalid FTP reply, non-ASCII characters; must be a 3-digit sequence followed by a space")
        if not re.match('[1-5][0-9][0-9] ', reply[0:4]):
            raise BooFtpException("Invalid FTP reply; must be a 3-digit sequence followed by a space")
        else:
            return reply[0:reply_code_len]


@click.command()
@click.option('--username', help='FTP username', prompt=True)
@click.option('--password', help='FTP password', prompt=True)
@click.pass_context
def ftp(ctx, username, password):
    cli_context = ctx.obj
    session = cli_context.session

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


if __name__ == "__main__":
    boofuzz.main_helper(click_command=ftp)
