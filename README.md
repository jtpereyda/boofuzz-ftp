# boofuzz-ftp
Simple FTP fuzzer to demonstrate boofuzz usage.

## Getting started

### Install boofuzz

    pip install boofuzz

Note: Check ftp.py for a specific boofuzz version number.

### Run an ftp server
Any server. Obscure open source projects are a nice place to look for bugs.

Since we're trying to break the program anyway, you may want to run it in a
Virtual Machine.

### Run the fuzzer

    python ftp.py  # > fuzz-logs.txt

It's fun to watch the fuzzer progress, but there is a lot of output.

### Watch it in action
Open your browser to [http://127.0.0.1:26000/]() to see progress.

Watch the ftp server under test to see if anything goes wrong.

## Improvements
This fuzzer could use:

1. A process monitor to start and stop the unit under test, and detect crashes.
2. Some recognition of received data to diagnose errors.
3. A fuller definition of FTP.
