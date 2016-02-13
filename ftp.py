#!/usr/bin/env python
from boofuzz import *


def main():
    logger = FuzzLogger(fuzz_loggers=[FuzzLoggerText()])
    session = sessions.Session(sleep_time=0.0, fuzz_data_logger=logger)

    my_connection = SocketConnection("127.0.0.1", 8021, proto='tcp')
    target = sessions.Target(my_connection)

    session.add_target(target)

    s_initialize("user")
    s_static("USER")
    s_delim(" ")
    s_static("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_static("PASS")
    s_delim(" ")
    s_static("james")
    s_string("\r\n")

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

    #     user
    #      |
    #     pass
    #    /    \
    #  stor   retr
    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))

    session.fuzz()


if __name__ == "__main__":
    main()
