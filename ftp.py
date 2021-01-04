#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3
from boofuzz import *
from boofuzz.constants import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.process_monitor_pedrpc_server import ProcessMonitorPedrpcServer
import click
from multiprocessing import Process


def serve_procmon(port, crash_bin, proc_name, ignore_pid, log_level):
    try:
        with ProcessMonitorPedrpcServer(
            host="0.0.0.0",
            port=port,
            crash_filename=crash_bin,
            debugger_class=DebuggerThreadSimple,
            proc_name=proc_name,
            pid_to_ignore=ignore_pid,
            level=log_level,
            coredump_dir="boofuzz-results",
        ) as servlet:
            servlet.serve_forever()
    except KeyboardInterrupt:
        return


@click.group()
def cli():
    pass


@click.command()
@click.option('--target-host', help='Host or IP address of target', prompt=True)
@click.option('--target-port', type=int, default=21, help='Network port of target', prompt=True)
@click.option('--username', help='FTP username', prompt=True)
@click.option('--password', help='FTP password', prompt=True)
@click.option('--test-case-index', help='Test case index', type=int)
@click.option('--test-case-name', help='Name of node or specific test case')
@click.option('--csv-out', help='Output to CSV file')
@click.option('--sleep-between-cases', help='Wait time between test cases (floating point)', type=float, default=0)
@click.option('--procmon-host', help='Process monitor port host or IP')
@click.option('--procmon-port', type=int, default=26002, help='Process monitor port')
@click.option('--procmon-start', help='Process monitor start command')
@click.option('--tui/--no-tui', help='Enable/disable TUI')
@click.argument('target_cmdline', nargs=-1, type=click.UNPROCESSED)
def fuzz(target_cmdline, target_host, target_port, username, password, test_case_index, test_case_name, csv_out,
         sleep_between_cases,
         procmon_host, procmon_port, procmon_start, tui):
    local_procmon = None
    if len(target_cmdline) > 0 and procmon_host is None:
        local_procmon = Process(target=serve_procmon,
                                kwargs={"port": 26002, "crash_bin": "boofuzz-crash-bin",
                                        "proc_name": None,  # "proftpd",
                                        "ignore_pid": None,
                                        "log_level": 1})
        local_procmon.start()
        procmon_host = "127.0.0.1"
    # serve_procmon(port=26002, crash_bin="boofuzz-crash-bin", proc_name="proftpd", ignore_pid=None, log_level=1)

    fuzz_loggers = []
    if tui:
        fuzz_loggers.append(FuzzLoggerCurses())
    if csv_out is not None:
        f = open('ftp-fuzz.csv', 'wb')
        fuzz_loggers.append(FuzzLoggerCsv(file_handle=f))

    procmon_options = {}
    if procmon_start is not None:
        procmon_options['start_commands'] = [procmon_start]
    if target_cmdline is not None:
        procmon_options['start_commands'] = [list(target_cmdline)]

    if procmon_host is not None or len(target_cmdline) > 0:
        if procmon_host is None:
            procmon_host = "127.0.0.1"
        procmon = ProcessMonitor(procmon_host, procmon_port)
        procmon.set_options(**procmon_options)
        monitors=[procmon]
    else:
        procmon = None
        monitors = []


    session = Session(
        target=Target(
            connection=TCPSocketConnection(target_host, target_port),
            monitors=monitors,
            # procmon=procmon,
            # procmon_options=procmon_options,
        ),
        fuzz_loggers=fuzz_loggers,
        sleep_time=sleep_between_cases,
    )

    initialize_ftp(session, username, password)

    if test_case_index is not None:
        session.fuzz_single_case(mutant_index=test_case_index)
    elif test_case_name is not None:
        session.fuzz_by_name(test_case_name)
    else:
        session.fuzz()

    if local_procmon is not None:
        local_procmon.kill()


def initialize_ftp(session, username, password):
    s_initialize("user")
    s_string("USER", name="USER-cmd")
    s_delim(" ", name="USER-delim")
    s_string(username.encode('ascii'), name="USER-val")
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS", name="PASS-cmdval")
    s_delim(" ", name="PASS-delim")
    s_string(password.encode('ascii'), name="PASS-val")
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR", name="STOR-cmd")
    s_delim(" ", name="STOR-delim")
    s_string("AAAA", name="STOR-val")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR", name="RETR-cmd")
    s_delim(" ", name="RETR-delim")
    s_string("AAAA", name="RETR-val")
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))


cli.add_command(fuzz)

if __name__ == "__main__":
    cli()
