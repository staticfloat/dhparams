#!/usr/bin/env python

# Requires flask and watchdog, install via pip
from os import mkdir
import os.path
import time
from threading import Thread
from subprocess import Popen, PIPE, STDOUT
from flask import Flask, request, Response, send_from_directory, jsonify
from werkzeug import secure_filename
import logging
app = Flask(__name__)

# Generate 4096-bit and 2048-bit dhparam files
keysizes = ['2048', '4096']

# Minimum number of keys to keep on hand
num_keys = 10

# Make directory for keys
root = os.path.dirname(os.path.realpath(__file__))
dhroot = os.path.join(root, 'dhparam_storage')
try:
    mkdir(dhroot)
except:
    pass

dhparamfiles = {keysize:[] for keysize in keysizes}

def random_filename(bits):
    from random import sample
    from string import digits, ascii_uppercase, ascii_lowercase

    frand = lambda: ''.join(sample(ascii_lowercase + ascii_uppercase + digits, 8))
    modnar = "%s_%s.key"%(bits, frand())
    while os.path.exists(os.path.join(dhroot,modnar)):
        modnar = "%s_%s.key"%(bits, frand())
    return modnar


def make_dhparam(bits):
    from os import devnull
    if not bits in keysizes:
        app.logger.error('Incorrect number of bits %s in make_dhparam()!'%(bits))
        return

    FNULL = open(devnull, 'w')
    fname = random_filename(bits)
    p = Popen(['openssl', 'dhparam', '-out', fname, bits], cwd=dhroot, stdout=FNULL, stderr=FNULL)
    if p.wait() != 0:
        app.logger.error('Could not generate %s-bit key in make_dhparam()!'%(bits))


def check_dhparam(fname):
    from os import devnull
    FNULL = open(devnull, 'w')

    p = Popen(['openssl', 'dhparam', '-in', fname], cwd=dhroot, stdout=FNULL, stderr=FNULL)
    return p.wait() == 0

def add_dhparamfile(path):
    # Stuff we always need to do
    fname = os.path.basename(path)
    bits = fname.split('_')[0]

    # Filter out wrong bits
    if not bits in keysizes:
        return

    if check_dhparam(fname) and not fname in dhparamfiles[bits]:
        dhparamfiles[bits] += [fname]

def del_dhparamfile(path):
    # Stuff we always need to do
    fname = os.path.basename(path)
    bits = fname.split('_')[0]

    # Filter out wrong bits
    if not bits in keysizes:
        return

    dhparamfiles[bits].remove(fname)


from watchdog.events import PatternMatchingEventHandler
class DirHandler(PatternMatchingEventHandler):
    patterns = ["*.key"]

    def process(self, event):
        """
        event.event_type
            'modified' | 'created' | 'moved' | 'deleted'
        event.is_directory
            True | False
        event.src_path
            path/to/observed/file
        """
        if event.event_type == 'created':
            add_dhparamfile(event.src_path)

        if event.event_type == 'deleted':
            del_dhparamfile(event.src_path)


    def on_created(self, event):
        self.process(event)

    def on_deleted(self, event):
        self.process(event)

def monitor_loop(observer):
    try:
        while observer.isAlive():
            # Always sleep for a bit
            time.sleep(1)

            # Generate new keys, if we need to.
            for keysize in keysizes:
                if observer.isAlive() and len(dhparamfiles[keysize]) < num_keys:
                    app.logger.info('Generating %s-bit key since we only have %d...'%(keysize, len(dhparamfiles[keysize])))
                    make_dhparam(keysize)
                    app.logger.info('Done generating!')
    except KeyboardInterrupt:
        pass
    app.logger.info('Exiting monitor loop!')


def start_monitor():
    from watchdog.observers import Observer
    from watchdog.events import LoggingEventHandler

    # Initialize dhparamfiles with what we have
    for fname in os.listdir(dhroot):
        add_dhparamfile(fname)

    observer = Observer()
    observer.schedule(DirHandler(), path=dhroot)
    observer.start()

    monitor_thread = Thread(target=monitor_loop, args=(observer,))
    monitor_thread.start()

    return observer, monitor_thread



@app.route('/get/<bits>')
def get_dhparam(bits):
    from random import sample

    if not bits in keysizes:
        return "Invalid bits %s"%(bits)

    if len(dhparamfiles[bits]) < 1:
        return "Temporarily out of magic numbers, sorry!"

    fname = sample(dhparamfiles[bits], 1)[0]
    return send_from_directory(dhroot, fname, attachment_filename="dhparams.key", as_attachment=True)

@app.route('/')
def status():
    msg = '<html><head><title>Diffie-Helman parameter distributor</title></head><body>Status: <br />\n'
    for keysize in keysizes:
        msg += '%d %s-bit keys available <br />\n'%(len(dhparamfiles[keysize]), keysize)
    msg += '<br />\n<br />\n'
    url = "/get/%s"%(keysizes[0])
    msg += 'Example usage: query <a href="%s">%s</a> to download a %s-bit dhparams.key file.'%(url, url, keysizes[0])
    msg += '\n<br /></body></html>'
    return msg

if __name__ == "__main__":
    try:
        monitor, monitor_thread = start_monitor()

        app.logger.setLevel(logging.INFO)
        app.run(port=5001)
    finally:
        app.logger.info("Stopping monitor...")
        monitor.stop()
        monitor.join()
        monitor_thread.join()
        app.logger.info("Done stopping monitor!")
