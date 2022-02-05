#!/usr/bin/env python
import subprocess
import argparse
import sys
import hashlib
import os.path
try:
    import cPickle as pickle
except ImportError:
    import _pickle as pickle
import re

# Split cppcheck and additional arguments.
ccpcheck_argv = list()
argc = len(sys.argv)
# Always true, just in case...
use_filter = False
use_xmlFilter = False
if argc > 0:
    try:
        sep = sys.argv.index('--')
        # Separator was not found
        if sep > 0:
            ccpcheck_argv = sys.argv[1:sep]
        if sep < argc:
            sys.argv = [sys.argv[0]] + sys.argv[sep+1:]
        else:
            sys.argv = [sys.argv[0]]
        use_filter = True
    except ValueError:
        # Separator was not found
        ccpcheck_argv = sys.argv[1:]

# Check that no forbidden parameters are passed to cppcheck.
if use_filter:
    forbidden_args = ['-h', '--help', '--help', '--xml-version=1']
    inv_args = list(set(ccpcheck_argv) & set(forbidden_args))
    #if len(inv_args) > 0:
    #    print('Incompatible cppcheck arguments:')
    #    print ", ".join(inv_args)
    #    sys.exit(1)
    use_filter = len(inv_args) == 0
    if use_filter:
        xml_args = ['--xml']
        use_xmlFilter = len(list(set(ccpcheck_argv) & set(xml_args))) != 0


class AbstractFilter(object):
    def is_active(self):
        raise NotImplementedError("Should have implemented this")

    def get_filename(self):
        raise NotImplementedError("Should have implemented this")

    def process(self, line):
        raise NotImplementedError("Should have implemented this")


class Filter(AbstractFilter):
    _filename = ''
    _read_mode = True
    _overwrite = False
    _lines_dict = {}

    def __init__(self, args, read_mode=True, filename='', overwrite=True):
        if filename:
            self._filename = str(filename)
        else:
            self._filename = self._compute_hash_filename(args)
        self._read_mode = bool(read_mode)
        self._overwrite = bool(overwrite)
        self._read()

    def __del__(self):
        self._write()

    def is_active(self):
        return not self._read_mode or self._lines_dict

    def get_filename(self):
        return self._filename

    @staticmethod
    def _compute_hash_filename(args):
        #m = hashlib.md5()
        #m.update("".join(args))
        #return m.hexdigest() + '.pickle'
        return "cppcheck.pickle"

    def _read(self):
        self._lines_dict.clear()
        if self._read_mode and self._filename:
            try:
                with open(self._filename, 'rb') as file:
                    self._lines_dict = pickle.load(file)
            except IOError:
                sys.stderr.write(
                    'Warning: file `{}` not found. Ignoring...\n'.
                    format(self._filename)
                )
        return self._lines_dict

    def _write(self):
        if not self._read_mode and self.is_active() and self._filename:
            if not self._overwrite and os.path.isfile(self._filename):
                sys.stderr.write(
                    'Warning: file `{}` already exists. '
                    'Use --force (-f) option to overwrite file.\n'.
                    format(self._filename)
                )
                return
            with open(self._filename, 'wb') as file:
                pickle.dump(self._lines_dict, file)

    def process(self, line):
        # Write mode (no filter at all).
        if not self._read_mode:
            self._lines_dict[str(line)] = None
            return True
        # Read mode (filter all input).
        else:
            return line not in self._lines_dict


class XmlFilter(AbstractFilter):

    class Error(object):
        id = ''
        severity = ''
        msg = ''
        file = ''
        line = 0
        node = ''

        def is_valid(self):
            return self.id

        def get_suppress_format(self):
            if self.is_valid():
                if self.file:
                    if self.line:
                        return '[%s]:[%s]:[%d]' % (self.id, self.file, self.line)
                    else:
                        return '[%s]:[%s]' % (self.id, self.file)
                else:
                    return '[%s]' % self.id
            return None

        def reset(self):
            self.id = ''
            self.severity = ''
            self.msg = ''
            self.file = ''
            self.line = 0
            self.node = ''

    _filename = ''
    _read_mode = True
    _overwrite = False
    _lines_dict = {}
    _error_node = Error()
    _start_re = re.compile('^ {8}<error id="([^"]+)" severity="([^"]+)" msg="([^"]+)" verbose="[^"]+"(/?)>\n$')
    _location_re = re.compile('^ {12}<location file="([^"]+)" line="([^"]+)"/>\n$')
    _end_re = re.compile('^ {8}</error>\n$')

    def __init__(self, args, read_mode=True, filename='', overwrite=True):
        if filename:
            self._filename = str(filename)
        else:
            self._filename = self._compute_hash_filename(args)
        self._read_mode = bool(read_mode)
        self._overwrite = bool(overwrite)
        self._read()

    def __del__(self):
        self._write()

    def is_active(self):
        return not self._read_mode or self._lines_dict

    def get_filename(self):
        return self._filename

    @staticmethod
    def _compute_hash_filename(args):
        return "cppcheck.pickle"

    def _read(self):
        self._lines_dict.clear()
        if self._read_mode and self._filename:
            try:
                with open(self._filename, 'r') as file:
                    self._lines_dict = pickle.load(file)
            except IOError:
                sys.stderr.write(
                    'Warning: file `{}` not found. Ignoring...\n'.
                    format(self._filename)
                )
        return self._lines_dict

    def _write(self):
        if not self._read_mode and self.is_active() and self._filename:
            if not self._overwrite and os.path.isfile(self._filename):
                sys.stderr.write(
                    'Warning: file `{}` already exists. '
                    'Use --force (-f) option to overwrite file.\n'.
                    format(self._filename)
                )
                return
            with open(self._filename, 'w') as file:
                pickle.dump(self._lines_dict, file)

    def process(self, line):
        suppress_line = self._parse_line(str(line))
        # Write mode (no filter at all).
        if not self._read_mode:
            if type(suppress_line) is str:
                self._lines_dict[suppress_line] = None
            return True
        # Read mode (filter all input).
        else:
            if type(suppress_line) is bool:
                # True if output is not an error node component, False if waiting to be tested.
                return suppress_line
            elif suppress_line not in self._lines_dict:
                # Output does not belong to file.
                return self._error_node.node
            else:
                # Output belongs to file.
                return False

    def _parse_line(self, line):
        # Detect error node beginning (extract id severity, msg).
        m = self._start_re.match(line)
        if m:
            self._error_node.reset()
            self._error_node.node = str(line)
            self._error_node.id = str(m.group(1))
            self._error_node.severity = str(m.group(2))
            self._error_node.msg = str(m.group(3))
            if m.group(4):
                return self._error_node.get_suppress_format()
        else:
            # Append to node value.
            self._error_node.node += str(line)
            # Detect error node beginning (extract id severity, msg).
            m = self._location_re.match(line)
            if m:
                self._error_node.file = str(m.group(1))
                self._error_node.line = int(m.group(2))
            else:
                # Detect error node beginning (extract id severity, msg).
                m = self._end_re.match(line)
                if m:
                    return self._error_node.get_suppress_format()
                else:
                    return True
        return False


filter = None
if use_filter:
    # Argument configuration for additional parameters only.
    parser = argparse.ArgumentParser(description='Substitute cppcheck standard call.')
    parser.add_argument('-ccp', '--cppcheck-path', dest='cppcheck_path',
                        default='cppcheck', type=str,
                        help='Path to cppcheck binary file (default: cppcheck).')
    parser.add_argument('-sp', '--save-path', dest='save_path',
                        default='', type=str,
                        help='Path to read or save file containing cppcheck output.')
    parser.add_argument('-w', '--write', dest='read_mode', action='store_const',
                        const=False, default=True,
                        help='Activate write mode (save generated outputs).')
    parser.add_argument('-f', '--force', dest='overwrite', action='store_const',
                        const=True, default=False,
                        help='Overwrite output file if already exists.')
    parser.add_argument('-d', '--disable-filter', dest='no_filter', action='store_const',
                        const=True, default=False,
                        help='Disable filtering with this option.')
    # Raise exceptions but well managed anyway.
    args = parser.parse_args()
    # Configure cppcheck path.
    cppcheck_path = args.cppcheck_path
    # Check if filter was disabled.
    if not args.no_filter:
        # Build filter object from cppcheck arguments.
        if not use_xmlFilter:
            filter = Filter(ccpcheck_argv, args.read_mode, args.save_path, args.overwrite)
        else:
            filter = XmlFilter(ccpcheck_argv, args.read_mode, args.save_path, args.overwrite)
        # If nothing is read, disable the filter.
        if not filter.is_active():
            filter = None
else:
    cppcheck_path = 'cppcheck'

try:
    # Prepend cppcheck path.
    ccpcheck_argv.insert(0, cppcheck_path)
    # Open cppcheck as subprocess.
    proc = subprocess.Popen(ccpcheck_argv, stderr=subprocess.PIPE)
    while True:
        line = proc.stderr.readline().decode('utf-8')
        if line != '':
            if filter is not None:
                process_line = filter.process(line)
                if type(process_line) is str:
                    sys.stderr.write(process_line)
                elif process_line:
                    sys.stderr.write(line)
            else:
                sys.stderr.write(line)
        else:
            filter = None
            break
except OSError as e:
    # Usually file not found error.
    sys.stderr.write('Fail to run: {}\nbecause: {}\n'.format(" ".join(ccpcheck_argv), e))
