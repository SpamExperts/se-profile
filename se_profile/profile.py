#! /usr/bin/env python

from __future__ import absolute_import, division, print_function

import os
import sys
import glob
import time
import logging
import inspect
import tarfile
import argparse
import functools
import importlib
import itertools
import linecache
import traceback
import collections

import psutil
import memory_profiler

logger = logging.getLogger("se-profiler")
PY3 = int(sys.version[0]) > 2


def setup_logging(logger, filename=None, stream_level=None, watched=False,
                  logdir="/var/log"):
    """Initialize logging for this logger. This add adds a file
    handler to `/var/log/` (or `/tmp/` if writing to /var/log/ is not allowed).

    :param logger: The logger that should be initialized.
    :param filename: The filename.
    :param stream_level: If specified add a stream handler
      and set it to that level
    :param logdir: Path where the log file is going to be written
    """
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    logger.setLevel(logging.DEBUG)

    file_class = logging.FileHandler
    if watched:
        file_class = logging.handlers.WatchedFileHandler

    if filename:
        filename = "%s/%s.log" % (logdir, filename)
        file_handler = file_class(filename)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)

    if stream_level is not None:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(getattr(logging, stream_level))
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)


def setup_script_logging(logger, filename=None, debug=False, info=False,
                         watched=False, logdir="/var/log/"):
    """Shortcut for setting up logging in scripts."""
    if debug:
        stream_level = "DEBUG"
    elif info:
        stream_level = "INFO"
    else:
        stream_level = "CRITICAL"
    setup_logging(logger, filename, stream_level=stream_level,
                  watched=watched, logdir=logdir)


class SkipMethod(Exception):
    pass


class CustomCodeMap(memory_profiler.CodeMap):
    """Abstract class that allows custom definitions
    of the trace function.
    """

    def trace(self, code, lineno):
        value = self.trace_func(-1, include_children=self.include_children)
        # if there is already a measurement for that line get the max
        previous_value = self[code].get(lineno, 0)
        self[code][lineno] = max(value, previous_value)

    def trace_func(self, pid, timestamps=False, include_children=False):
        raise NotImplementedError()


class MemoryCodeMap(CustomCodeMap):
    """Just like the original from the memory_profiler library."""

    def trace_func(self, pid, timestamps=False, include_children=False):
        return memory_profiler._get_memory(pid, timestamps=timestamps,
                                           include_children=include_children)


class MemoryUSSCodeMap(CustomCodeMap):
    """Just like the original from the memory_profiler library
    but records USS memory instead of RSS
    """

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            memory_info = proc.memory_full_info()
            total += memory_info.uss / 2 ** 20

        if timestamps:
            return total, time.time()
        return total


class MemoryPSSCodeMap(CustomCodeMap):
    """Just like the original from the memory_profiler library
    but records PSS memory instead of RSS
    """

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            memory_info = proc.memory_full_info()
            total += memory_info.pss / 2 ** 20

        if timestamps:
            return total, time.time()
        return total


class CPUCodeMap(CustomCodeMap):
    """Traces CPU of the process."""

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            cpu_times = proc.cpu_times()
            total += cpu_times.user + cpu_times.system

        if timestamps:
            return total, time.time()
        return total


class IOReadCodeMap(CustomCodeMap):
    """Traces read IO of the process."""

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            io_counters = proc.io_counters()
            total += io_counters.read_bytes / 2 ** 10

        if timestamps:
            return total, time.time()
        return total


class IOReadCountCodeMap(CustomCodeMap):
    """Traces read IO of the process."""

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            io_counters = proc.io_counters()
            total += io_counters.read_count

        if timestamps:
            return total, time.time()
        return total


class IOWriteCodeMap(IOReadCodeMap):
    """Traces write IO of the process."""

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            io_counters = proc.io_counters()
            total += io_counters.write_bytes / 2 ** 10

        if timestamps:
            return total, time.time()
        return total


class IOWriteCountCodeMap(IOReadCodeMap):
    """Traces write IO of the process."""

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            io_counters = proc.io_counters()
            total += io_counters.write_count

        if timestamps:
            return total, time.time()
        return total


class IOCountCodeMap(IOReadCodeMap):
    """Traces IO count (writea and read) of the process."""

    def trace_func(self, pid, timestamps=False, include_children=False):
        if pid == -1:
            pid = os.getpid()

        parent_proc = psutil.Process(pid)
        procs = [parent_proc]
        if include_children:
            procs += parent_proc.children()

        total = 0
        for proc in procs:
            io_counters = proc.io_counters()
            total += io_counters.write_count + io_counters.read_count

        if timestamps:
            return total, time.time()
        return total


class CustomLineProfiler(memory_profiler.LineProfiler):
    code_map_klass = memory_profiler.CodeMap

    def __init__(self, **kw):
        super(CustomLineProfiler, self).__init__(**kw)
        include_children = kw.get('include_children', False)
        self.code_map = self.code_map_klass(include_children)

    def trace_memory_usage(self, frame, event, arg):
        """Callback for sys.settrace"""
        if frame.f_code in self.code_map:
            try:
                if event == 'call':
                    # "call" event just saves the lineno but not the memory
                    self.prevlines.append(frame.f_lineno)
                elif event == 'line':
                    self.code_map.trace(frame.f_code, self.prevlines[-1])
                    self.prevlines[-1] = frame.f_lineno
                elif event == 'return':
                    self.code_map.trace(frame.f_code, self.prevlines.pop())
            except IndexError:
                # Unclear what happens here :/
                pass

        if self._original_trace_function is not None:
            (self._original_trace_function)(frame, event, arg)

        return self.trace_memory_usage


class MemoryLineProfiler(CustomLineProfiler):
    code_map_klass = MemoryCodeMap


class MemoryUSSLineProfiler(CustomLineProfiler):
    code_map_klass = MemoryUSSCodeMap


class MemoryPSSLineProfiler(CustomLineProfiler):
    code_map_klass = MemoryPSSCodeMap


class CPULineProfiler(CustomLineProfiler):
    code_map_klass = CPUCodeMap


class IOReadLineProfiler(CustomLineProfiler):
    code_map_klass = IOReadCodeMap


class IOWriteLineProfiler(CustomLineProfiler):
    code_map_klass = IOWriteCodeMap


class IOReadCountLineProfiler(CustomLineProfiler):
    code_map_klass = IOReadCountCodeMap


class IOWriteCountLineProfiler(CustomLineProfiler):
    code_map_klass = IOWriteCountCodeMap


class IOCountLineProfiler(CustomLineProfiler):
    code_map_klass = IOCountCodeMap


class CustomProfiler(object):
    unit = ""
    name = "Value"
    profiler_klass = memory_profiler.LineProfiler
    cumulative = False

    def __init__(self, test_name, precision=3):
        self.test_name = test_name
        self.all_max = None
        self.all_min = None
        self.all_avg = None
        self.start_value = None
        self.end_value = None
        self.precision = precision
        self.functions = set()
        self.modules = set()
        self.klasses = set()
        self.prof = self.profiler_klass(include_children=False)

    def profile_func(self, func):
        """Wrapped the function with the profile decorator."""

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.prof(func)(*args, **kwargs)

        return wrapper

    def profile_method(self, klass, method, name):
        if PY3:
            return self.profile_method_3(klass, method, name)
        return self.profile_method_2(klass, method, name)

    def profile_method_3(self, klass, method, name):
        """Wraps the method of class to be profiled."""
        try:
            function = klass.__dict__[name]
            if isinstance(function, staticmethod):
                raw_function = function.__func__
                logger.debug("Profiling staticmethod: %s", method)
                decorated_method = self.profile_func(raw_function)
                decorated_method = staticmethod(decorated_method)
            elif isinstance(function, classmethod):
                raw_function = function.__func__
                logger.debug("Profiling classmethod: %s", method)
                decorated_method = self.profile_func(raw_function)
                decorated_method = classmethod(decorated_method)
            else:
                logger.debug("Profiling method: %s", method)
                decorated_method = self.profile_func(method)
        except KeyError:
            # This method is actually inherited.
            logger.debug("Inherited method: %s", method)
            raise SkipMethod()
        return decorated_method

    def profile_method_2(self, klass, method, name):
        """Wraps the method of class to be profiled."""
        # Digging deep in Python internal here
        decorated_method = method
        try:
            # staticmethod
            if not hasattr(method, "__self__"):
                raw_function = klass.__dict__[name].__func__
                logger.debug("Profiling staticmethod: %s", method)
                decorated_method = self.profile_func(raw_function)
                decorated_method = staticmethod(decorated_method)
            # classmethod
            elif method.__self__ is klass:
                raw_function = klass.__dict__[name].__func__
                logger.debug("Profiling classmethod: %s", method)
                decorated_method = self.profile_func(raw_function)
                decorated_method = classmethod(decorated_method)
            # instance method
            elif method.__self__ is None:
                logger.debug("Profiling method: %s", method)
                decorated_method = self.profile_func(method)
        except KeyError:
            # This method is actually inherited.
            logger.debug("Inherited method: %s", method)
            raise SkipMethod()
        return decorated_method

    def profile_class(self, klass):
        if klass in self.klasses:
            # Already profiled.
            logger.debug("Class already profiled: %s", klass)
            return

        try:
            modulef = inspect.getfile(klass)
            if "python2" in modulef or "python3" in modulef:
                # Must be something from the site-packages
                return
            if klass.__name__.startswith("__"):
                return
        except TypeError:
            # Must be a built-in
            return
        logger.debug("Profiling class: %s", klass)
        for name in dir(klass):
            method = getattr(klass, name, None)
            if not method or name.startswith("__"):
                continue
            if not inspect.ismethod(method) and not inspect.isfunction(method):
                continue
            try:
                profiled_method = self.profile_method(klass, method, name)
            except SkipMethod:
                continue
            setattr(klass, name, profiled_method)

        self.klasses.add(klass)

    def profile_all(self):
        """Profile all the function from all the modules
        from `sys.modules`.

        This only applies to modules from this project
        and not any of the built-ins or pip installed
        projects.
        """
        for name, module in list(sys.modules.items()):
            if module is None:
                continue
            self.profile_module(module)
        del self.functions
        del self.modules
        del self.klasses

    def profile_module(self, module):
        """Add the profile to all the functions in
        this module.
        """
        if module in self.modules:
            # Already profiled.
            logger.debug("Module already profiled: %s", module)
            return

        try:
            modulef = inspect.getfile(module)
            if "python2" in modulef or "python3" in modulef:
                # Must be something from the site-packages
                return
            if module.__name__.startswith("__"):
                return
        except TypeError:
            # Must be a built-in
            return

        logger.debug("Profiling module: %s", module)
        for obj_name in dir(module):
            obj = getattr(module, obj_name, None)
            if not obj or obj_name.startswith("__"):
                continue
            elif inspect.isfunction(obj):
                if obj in self.functions:
                    continue
                logger.debug("Profiling function: %s", obj_name)
                setattr(module, obj_name, self.profile_func(obj))
                self.functions.add(obj)
            elif inspect.isclass(obj):
                self.profile_class(obj)
            else:
                continue
        self.modules.add(module)

    def show_results(self, fp=None):
        """Print the results to this file."""
        if fp is None:
            self._show_results(
                stream=sys.__stdout__, precision=self.precision
            )
        else:
            with open(fp, "w") as proff:
                self._show_results(
                    stream=proff, precision=self.precision
                )

    def show_results_per_file(self, fp=None):
        if fp is None:
            stream = sys.__stdout__
        else:
            stream = open(fp, "w")
        try:
            for filename in self.get_filenames():
                self.show_results_for_file(stream, filename)
        finally:
            stream.close()

    def get_filenames(self):
        """Get a list of profiled filenames"""
        return set(filename for filename, _ in self.prof.code_map.items())

    def show_results_for_file(self, stream, result_filename):
        if stream is None:
            stream = sys.stdout
        float_format = '{0}.{1}f'.format(self.precision + 4, self.precision)
        template_val = '{0:' + float_format + '} %s' % self.unit
        template = '{0:>6} {1:>12} {2:>12}   {3:<}'

        results = {}
        for filename, lines in self.prof.code_map.items():
            if result_filename != filename:
                continue
            old = None
            for lineno, value in lines:
                if not value:
                    continue
                inc = (value - old) if old is not None else 0
                old = value
                results[lineno] = (value, inc)

        all_lines = linecache.getlines(result_filename)
        header = template.format('Line #', '%s usage' % self.name,
                                 'Increment', 'Line Contents')
        stream.write(header + '\n')

        for lineno, line in enumerate(all_lines):
            try:
                val, inc = results[lineno + 1]
            except IndexError:
                val, inc = '', ''
            val = template_val.format(val)
            inc = template_val.format(inc)
            tmp = template.format(lineno, val, inc, line)
            stream.write(str(tmp))
        stream.write('\n')

    def _show_results(self, stream=None, precision=1):
        if stream is None:
            stream = sys.stdout
        template = '{0:>6} {1:>12} {2:>12}   {3:<}'

        for filename, lines in self.prof.code_map.items():
            header = template.format('Line #', '%s usage' % self.name,
                                     'Increment', 'Line Contents')

            stream.write('Filename: ' + filename + '\n\n')
            stream.write(header + '\n')
            stream.write('=' * len(header) + '\n')

            all_lines = linecache.getlines(filename)
            mem_old = None
            float_format = '{0}.{1}f'.format(precision + 4, precision)
            template_mem = '{0:' + float_format + '} %s' % self.unit
            for (lineno, mem) in lines:
                if mem is not None:
                    inc = (mem - mem_old) if mem_old else 0
                    mem_old = mem
                    mem = template_mem.format(mem)
                    inc = template_mem.format(inc)
                else:
                    mem = ''
                    inc = ''
                tmp = template.format(lineno, mem, inc, all_lines[lineno - 1])
                stream.write(str(tmp))
            stream.write('\n\n')

    def print_report(self, fp=None):
        """Print a report for each file and total.

        Shows the max, min, average for each filename
        and total.
        """
        full_sep = "-" * 99 + "\n"
        table_sep = " " * 4 + "=" * 91 + "\n"
        float_format = '{0}.{1}f'.format(self.precision + 4, self.precision)
        template_mem = '{0:' + float_format + '} '
        template = '    |{0:>12} {1:>12} {2:>12} {3:<50}|\n'
        if fp is not None:
            stream = open(fp, "w")
        else:
            stream = sys.__stdout__
        stream.write("\n" + self.test_name + "\n")
        stream.write(full_sep)
        count = 0
        total = 0
        report = collections.defaultdict(list)
        for filename, lines in self.prof.code_map.items():
            if "python2" in filename or "python3" in filename:
                continue
            if os.path.isabs(filename):
                filename = filename[len(os.getcwd()):].strip(os.path.sep)
            for mem in lines:
                if mem is None or mem[1] is None:
                    continue
                report[filename].append(mem[1])
                total += mem[1]
                count += 1

        stream.write(table_sep)
        if self.cumulative:
            stream.write(template.format("Max %s" % self.unit,
                                         "Min %s" % self.unit,
                                         "Inc %s" % self.unit,
                                         "FILE"))
        else:
            stream.write(template.format("Max %s" % self.unit,
                                         "Min %s" % self.unit,
                                         "Avg %s" % self.unit,
                                         "FILE"))
        stream.write(table_sep)

        results = []
        for filename, values in report.items():
            fmin = min(values)
            fmax = max(values)
            favg = sum(values) / len(values)
            finc = fmax - fmin
            if self.cumulative:
                results.append((fmax, fmin, finc, filename))
            else:
                results.append((fmax, fmin, favg, filename))
        if self.cumulative:
            results.sort(key=lambda x: x[2], reverse=True)
        else:
            results.sort(key=lambda x: x[0], reverse=True)
        for fmax, fmin, favg, filename in results:
            stream.write(template.format(
                template_mem.format(fmax),
                template_mem.format(fmin),
                template_mem.format(favg),
                filename
            ))
        stream.write(table_sep)
        if report:
            self.all_min = min(itertools.chain(*report.values()))
            self.all_max = max(itertools.chain(*report.values()))
        else:
            self.all_min = 0
            self.all_max = 0
        if self.cumulative:
            self.third = self.all_max - self.all_min
        else:
            self.third = total / count
        stream.write(template.format(
            template_mem.format(self.all_max),
            template_mem.format(self.all_min),
            template_mem.format(self.third),
            "TOTAL"
        ))
        stream.write(table_sep)

        template2 = " {0:>12} - {1:>}\n"
        stream.write("\n")
        stream.write(template2.format(
            template_mem.format(self.all_max),
            "%s peak" % self.name
        ))
        stream.write(template2.format(
            template_mem.format(self.start_value),
            "%s at import" % self.name
        ))
        stream.write(template2.format(
            template_mem.format(self.end_value),
            "%s at end of run" % self.name
        ))
        stream.write(template2.format(
            template_mem.format(self.end_value - self.start_value),
            "%s increment" % self.name
        ))
        stream.write(full_sep)
        stream.flush()

    def run_and_profile(self, module_name, args):
        """Run the main function of the specified
        module with the specified args and profile
        the memory.
        """

        def wrapped():
            sys.argv = args
            # Import the module here
            module = importlib.import_module(module_name)
            # Record the memory
            self.start_value = self.prof.code_map.trace_func(-1)
            # Wrap all ALL functions with the profiler
            self.profile_all()
            # Call the main function.
            module.main()
            self.end_value = self.prof.code_map.trace_func(-1)

        profiled_wrapped = self.profile_func(wrapped)
        profiled_wrapped()


class MemProfiler(CustomProfiler):
    unit = "MB"
    name = "Memory"
    cumulative = False
    profiler_klass = MemoryLineProfiler


class MemUSSProfiler(CustomProfiler):
    unit = "MB"
    name = "Memory USS"
    cumulative = False
    profiler_klass = MemoryUSSLineProfiler


class MemPSSProfiler(CustomProfiler):
    unit = "MB"
    name = "Memory PSS"
    cumulative = False
    profiler_klass = MemoryPSSLineProfiler


class CPUProfiler(CustomProfiler):
    unit = "s"
    name = "CPU"
    cumulative = True
    profiler_klass = CPULineProfiler


class IOReadProfiler(CustomProfiler):
    unit = "KB"
    name = "IO-read"
    cumulative = True
    profiler_klass = IOReadLineProfiler


class IOWriteProfiler(CustomProfiler):
    unit = "KB"
    name = "IO-write"
    cumulative = True
    profiler_klass = IOWriteLineProfiler


class IOReadCountProfiler(CustomProfiler):
    unit = ""
    name = "IO-read-count"
    cumulative = True
    profiler_klass = IOReadCountLineProfiler


class IOWriteCountProfiler(CustomProfiler):
    unit = ""
    name = "IO-write-count"
    cumulative = True
    profiler_klass = IOWriteCountLineProfiler


class IOCountProfiler(CustomProfiler):
    unit = ""
    name = "IO-count"
    cumulative = True
    profiler_klass = IOCountLineProfiler


def run_profiler(options, klass):
    """Run the profiler and print the report.

    Return True if the limits are respected and False
    otherwise.
    """
    prof = klass(options.name)

    original_path = options.module_name
    if os.path.sep in original_path:
        module_name = original_path.replace(".py", "").replace(".pyc", "")
        module_name = module_name.replace(os.path.sep, ".")
    else:
        module_name = original_path

    args = [original_path] + options.args.split()
    prof.run_and_profile(module_name, args)

    result_dest = os.path.join(options.destination,
                               options.short_name + "-result.txt")
    report_dest = os.path.join(options.destination,
                               options.short_name + "-report.txt")

    if options.per_file:
        prof.show_results_per_file(result_dest)
    else:
        prof.show_results(result_dest)
    prof.print_report(report_dest)
    if options.print_report:
        prof.print_report()
    ok = True
    if options.import_limit:
        if prof.start_value > options.import_limit:
            ok = False
            print("Import limit exceeded %s / %s" %
                  (prof.start_value, options.import_limit),
                  file=sys.__stderr__)
    if options.increment_limit:
        increment = prof.end_value - prof.start_value
        if increment > options.increment_limit:
            ok = False
            print("Increment limit exceeded %s / %s" %
                  (prof.start_value, options.increment_limit),
                  file=sys.__stderr__)
    if options.peak_limit:
        if prof.all_max > options.peak_limit:
            ok = False
            print("Peak limit exceeded %s / %s" %
                  (prof.all_max, options.peak_limit),
                  file=sys.__stderr__)
    if options.end_limit:
        if prof.end_value > options.end_limit:
            ok = False
            print("End limit exceeded %s / %s" %
                  (prof.end_value, options.end_limit),
                  file=sys.__stderr__)
    return ok


def get_growth_from_stats(current_stats):
    import objgraph
    new_stats = objgraph.typestats(shortnames=True)
    growth = []
    for type_, new_count in new_stats.items():
        if type_ == "frame":
            # This is an object that objgraph adds.
            # Skip it.
            continue
        old_count = current_stats.get(type_, 0)
        increment = new_count - old_count
        if increment > 0:
            growth.append((type_, new_count, increment))
    growth.sort(key=lambda x: x[2], reverse=True)
    return growth


def get_memory_leak_report(options):
    import objgraph
    import pympler.asizeof
    original_path = options.module_name
    if os.path.sep in original_path:
        module_name = original_path.replace(".py", "").replace(".pyc", "")
        module_name = module_name.replace(os.path.sep, ".")
    else:
        module_name = original_path

    args = [original_path] + options.args.split()
    sys.argv = args
    module = importlib.import_module(module_name)

    current_stats = objgraph.typestats(shortnames=True)
    for _ in range(options.init_step_count):
        module.main()
        # Get the baseline
        current_stats = objgraph.typestats(shortnames=True)

    total = 0
    growths = []
    for i in range(options.leak_step_count):
        logger.debug("Step %s", i)
        # Call the API again, and check the growth.
        # Ideally there is no growth after each call
        module.main()
        growth = get_growth_from_stats(current_stats)

        adj_growth = []
        for type_, new_count, inc in growth:
            fn = "%s-leak-step-%s-%s.png" % (options.short_name, i, type_)
            fn = os.path.join(options.destination, fn)
            leaked_objects = objgraph.by_type(type_)[-inc:]

            # Generate a graph for the leaked objects
            # up to a maximum of 100
            objgraph.show_backrefs(leaked_objects[:50], filename=fn)
            # Also get the size of the objects leaked
            size = pympler.asizeof.asized(leaked_objects).size / 2 ** 10
            total += size
            logger.debug("+%s: %r grew to %s (+%s KB)",
                         inc, type_, new_count, size)
            adj_growth.append((type_, new_count, inc, size))
        adj_growth.sort(key=lambda x: x[3], reverse=True)
        growths.append(adj_growth)
        # Update the current stats
        current_stats = objgraph.typestats(shortnames=True)
    return growths, total


def print_growth_report(growths, fp, name):
    full_sep = "-" * 85 + "\n"
    table_sep = " " * 4 + "=" * 81 + "\n"
    template = '    |{0:>30} | {1:>12} | {2:>12} | {3:>12} KB |\n'
    if fp is not None:
        stream = open(fp, "w")
    else:
        stream = sys.__stdout__

    headers = ["Type", "Count", "Increment", "Size"]

    stream.write("\nMemory leak test: %s\n\n" % name)
    for i, growth in enumerate(growths):
        stream.write("Step %s\n" % i)
        stream.write(full_sep)
        stream.write("\n")

        stream.write(table_sep)
        stream.write(template.format(*headers))
        stream.write(table_sep)

        total_size = 0
        total_increment = 0
        for ctype_, count, increment, size in growth:
            total_size += size
            total_increment += increment

            increment = "+%s" % increment
            size = "%.2f" % size
            stream.write(template.format(ctype_, count, increment, size))
        stream.write(table_sep)
        stream.write(template.format("Total", 'N/A', total_increment,
                                     "%.2f" % total_size))
        stream.write(table_sep)
        stream.write("\n")
    stream.write("\n")


def run_memory_leak_check(options):
    growths, total = get_memory_leak_report(options)

    fn = os.path.join(options.destination,
                      "%s-leak-report.txt" % (options.short_name,))
    print_growth_report(growths, fn, options.name)
    if options.print_report:
        print_growth_report(growths, None, options.name)
    if options.leak_limit and total > options.leak_limit:
        print("Import limit exceeded %s / %s" %
              (total, options.leak_limit), file=sys.__stderr__)
        return False
    return True


def get_default_options():
    """

    :return: parser.options
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--collect-gz", default=None,
                        help="Collect results from previous run into this "
                             "archive")
    parser.add_argument("--debug", default=False, action="store_true",
                        help="Activate debug logging.")
    parser.add_argument("-d", "--destination", default=".profile_results/",
                        help="Store the profile result in this folder")
    parser.add_argument("-n", "--name", default="Profiler",
                        help="Specify the test name")
    parser.add_argument("-s", "--short-name", default="profiler",
                        help="Specify the short name")
    parser.add_argument("-m", "--module-name", required=True,
                        help="Run this module's main function")
    parser.add_argument("-p", "--print-report",
                        action="store_true", default=False,
                        help="Print the report to stdout instead of file")
    parser.add_argument("--per-file",
                        action="store_true", default=False,
                        help="Collate the report per file instead of per "
                             "function")
    parser.add_argument("--import-limit", default=None, type=float,
                        help="Set the maximum at import time")
    parser.add_argument("--increment-limit", default=None, type=float,
                        help="Set the maximum at import time")
    parser.add_argument("--end-limit", default=None, type=float,
                        help="Set the maximum at end time")
    parser.add_argument("--peak-limit", default=None, type=float,
                        help="Set the maximum peak")
    parser.add_argument("--leak-limit", default=None, type=float,
                        help="Set the leak limit")
    parser.add_argument("-t", "--profile-type", default="memory",
                        choices=["memory", "memory-uss", "memory-pss",
                                 "cpu", "io-read", "io-write",
                                 "io-read-count", "io-write-count",
                                 "io-count", "memory-leak"],
                        help="Chose the type of profiling to be done.")
    parser.add_argument("--init-step-count", type=int, default=2,
                        help="The number of times to get the baseline for "
                             "memory-leak")
    parser.add_argument("--leak-step-count", type=int, default=1,
                        help="The number of times to get check the "
                             "memory leak after getting the baseline")
    parser.add_argument("args", nargs="?", default="",
                        help="Pass these arguments to the module")
    options = parser.parse_args()
    return options


def main():
    options = get_default_options()

    if setup_script_logging:
        try:
            setup_script_logging(logger, "se_profiler", debug=options.debug)
        except IOError:
            setup_script_logging(logger, "se_profiler", debug=options.debug,
                                 logdir="/tmp/")

    try:
        os.makedirs(options.destination)
    except OSError:
        pass

    klass = CustomProfiler
    if options.profile_type == "memory":
        klass = MemProfiler
    elif options.profile_type == "memory-uss":
        klass = MemUSSProfiler
    elif options.profile_type == "memory-pss":
        klass = MemPSSProfiler
    elif options.profile_type == "cpu":
        klass = CPUProfiler
    elif options.profile_type == "io-read":
        klass = IOReadProfiler
    elif options.profile_type == "io-write":
        klass = IOWriteProfiler
    elif options.profile_type == "io-read-count":
        klass = IOReadCountProfiler
    elif options.profile_type == "io-write-count":
        klass = IOWriteCountProfiler
    elif options.profile_type == "io-count":
        klass = IOCountProfiler

    if options.collect_gz:
        results = glob.glob(os.path.join(options.destination, "*"))
        with tarfile.open(options.collect_gz, "w:gz") as tar:
            for fn in results:
                tar.add(fn, os.path.join("profile", os.path.basename(fn)))
    elif options.profile_type == "memory-leak":
        try:
            if not run_memory_leak_check(options):
                sys.exit(1)
        except:
            traceback.print_exc(file=sys.__stderr__)
            sys.exit(1)
    else:
        try:
            result = run_profiler(options, klass)
            if not result:
                sys.exit(1)
        except:
            traceback.print_exc(file=sys.__stderr__)
            sys.exit(1)


if __name__ == "__main__":
    main()
