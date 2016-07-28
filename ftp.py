#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3
from boofuzz import *


def main():
    session = sessions.Session(
        target=sessions.Target(
            connection=SocketConnection("127.0.0.1", 8021, proto='tcp')))

    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS")
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


if __name__ == "__main__":
    main()
