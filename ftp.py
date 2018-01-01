#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3
from boofuzz import *
import click

@click.group()
def cli():
    pass

@click.command()
@click.option('--target-host', help='Host or IP address of target')
@click.option('--target-port', type=int, default=21, help='Network port of target')
@click.option('--username', help='FTP username')
@click.option('--password', help='FTP password')
def fuzz(target_host, target_port, username, password):
    session = Session(
        target=Target(
            connection=SocketConnection(target_host, target_port, proto='tcp')))

    s_initialize("user")
    s_string("boofuzz-user")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_string(password.encode('ascii'))
    s_delim(" ")
    s_string("james")
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
	
    session.fuzz()

cli.add_command(fuzz)

if __name__ == "__main__":
    cli()
