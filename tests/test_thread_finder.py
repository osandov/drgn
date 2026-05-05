# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import Architecture, Object, Platform, Program, RegisterState, ThreadFinder
from tests import TestCase


class SimpleThreadFinder(ThreadFinder):
    def threads(self, cache):
        for tid in (1, 2, 3):
            yield cache.find_or_create(tid, 0)[0]

    def thread(self, cache, tid):
        if tid in (1, 2, 3):
            return cache.find_or_create(tid, 0)[0]
        return None

    def main_thread(self, cache):
        return cache.find_or_create(1, 0)[0]

    def crashed_thread(self, cache):
        return cache.find_or_create(3, 0)[0]

    def thread_object(self, thread):
        return Object(thread.prog, "void *", thread.tid * 0x1000)

    def thread_name(self, thread):
        return f"thread-{thread.tid}"


class GenerationThreadFinder(ThreadFinder):
    def threads(self, cache):
        yield cache.find_or_create(1, 0)[0]
        yield cache.find_or_create(1, 1)[0]

    def thread(self, cache, tid):
        return cache.find_or_create(tid, 1)[0] if tid == 1 else None


class MainCrashedNoneThreadFinder(ThreadFinder):
    def main_thread(self, cache):
        return None

    def crashed_thread(self, cache):
        return None


class NameNoneThreadFinder(ThreadFinder):
    def thread(self, cache, tid):
        return cache.find_or_create(tid, 0)[0] if tid == 1 else None

    def thread_name(self, thread):
        return None


class EagerObjectThreadFinder(ThreadFinder):
    def thread(self, cache, tid):
        if tid not in (1, 2, 3):
            return None
        return cache.find_or_create(tid, 0, Object(cache.prog, "void *", tid * 0x1000))[
            0
        ]

    def thread_from_object(self, cache, obj):
        value = obj.value_()
        if value not in (0x1000, 0x2000, 0x3000):
            return None
        return cache.find_or_create(value // 0x1000, 0, obj)[0]


class TestException(Exception):
    pass


class ExceptionThreadFinder(ThreadFinder):
    def threads(self, cache):
        raise TestException("threads")

    def thread(self, cache, tid):
        if tid == 1:
            return cache.find_or_create(tid, 0)[0]
        elif tid == 2:
            raise TestException("thread")
        else:
            return None

    def main_thread(self, cache):
        raise TestException("main_thread")

    def crashed_thread(self, cache):
        raise TestException("crashed_thread")

    def thread_object(self, thread):
        raise TestException("thread_object")

    def thread_name(self, thread):
        raise TestException("thread_name")


def program_with_thread_finder(finder):
    prog = Program(platform=Platform(Architecture.X86_64))
    prog.register_thread_finder("test", finder, enable_index=0)
    return prog


class TestThreadFinder(TestCase):
    def test_threads(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertCountEqual([thread.tid for thread in prog.threads()], [1, 2, 3])

    def test_threads_generation(self):
        prog = program_with_thread_finder(GenerationThreadFinder())
        threads = list(prog.threads())
        self.assertEqual(len(threads), 2)
        self.assertEqual(threads[0].tid, 1)
        self.assertEqual(threads[1].tid, 1)
        self.assertEqual(threads[0].generation, 0)
        self.assertEqual(threads[1].generation, 1)
        self.assertIsNot(threads[0], threads[1])

    def test_threads_deduplication(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        t1 = prog.thread(1)
        self.assertIs(next(thread for thread in prog.threads() if thread.tid == 1), t1)

    def test_threads_default(self):
        prog = program_with_thread_finder(ThreadFinder())
        with self.assertRaises(ValueError):
            for _ in prog.threads():
                break

    def test_threads_no_finder(self):
        with self.assertRaises(ValueError):
            for _ in Program().threads():
                break

    def test_thread(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertEqual(prog.thread(1).tid, 1)

    def test_thread_generation(self):
        prog = program_with_thread_finder(GenerationThreadFinder())
        self.assertEqual(prog.thread(1).generation, 1)

    def test_thread_prog(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertEqual(prog.thread(1).prog, prog)

    def test_thread_not_found(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertRaises(LookupError, prog.thread, 99)

    def test_thread_deduplication(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        t1 = prog.thread(1)
        t2 = prog.thread(1)
        self.assertIs(t1, t2)

    def test_thread_default(self):
        prog = program_with_thread_finder(ThreadFinder())
        self.assertRaises(ValueError, prog.thread, 1)

    def test_thread_no_finder(self):
        self.assertRaises(ValueError, Program().thread, 1)

    def test_main_thread(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertEqual(prog.main_thread().tid, 1)

    def test_main_thread_not_found(self):
        prog = program_with_thread_finder(MainCrashedNoneThreadFinder())
        self.assertRaises(LookupError, prog.main_thread)

    def test_main_thread_default(self):
        prog = program_with_thread_finder(ThreadFinder())
        self.assertRaises(ValueError, prog.main_thread)

    def test_main_thread_no_finder(self):
        self.assertRaises(ValueError, Program().main_thread)

    def test_crashed_thread(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertEqual(prog.crashed_thread().tid, 3)

    def test_crashed_thread_not_found(self):
        prog = program_with_thread_finder(MainCrashedNoneThreadFinder())
        self.assertRaises(LookupError, prog.crashed_thread)

    def test_crashed_thread_default(self):
        prog = program_with_thread_finder(ThreadFinder())
        self.assertRaises(ValueError, prog.crashed_thread)

    def test_crashed_thread_no_finder(self):
        self.assertRaises(ValueError, Program().crashed_thread)

    def test_thread_name(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertEqual(prog.thread(1).name, "thread-1")
        self.assertEqual(prog.thread(2).name, "thread-2")

    def test_thread_name_none(self):
        prog = program_with_thread_finder(NameNoneThreadFinder())
        self.assertIsNone(prog.thread(1).name)

    def test_thread_name_default(self):
        prog = program_with_thread_finder(GenerationThreadFinder())
        self.assertIsNone(prog.thread(1).name)

    def test_thread_object_lazy(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        self.assertEqual(prog.thread(1).object, Object(prog, "void *", 0x1000))
        self.assertEqual(prog.thread(2).object, Object(prog, "void *", 0x2000))

    def test_thread_object_eager(self):
        prog = program_with_thread_finder(EagerObjectThreadFinder())
        self.assertEqual(prog.thread(1).object, Object(prog, "void *", 0x1000))
        self.assertEqual(prog.thread(2).object, Object(prog, "void *", 0x2000))

    def test_thread_from_object(self):
        prog = program_with_thread_finder(EagerObjectThreadFinder())
        obj = Object(prog, "void *", 0x1000)
        thread = prog.thread_from_object(obj)
        self.assertEqual(thread.tid, 1)
        self.assertEqual(thread.object, obj)

    def test_thread_from_object_not_found(self):
        prog = program_with_thread_finder(EagerObjectThreadFinder())
        self.assertRaises(
            LookupError, prog.thread_from_object, Object(prog, "void *", 0x1001)
        )

    def test_thread_from_object_wrong_program(self):
        prog = program_with_thread_finder(EagerObjectThreadFinder())
        other_prog = Program(platform=Platform(Architecture.X86_64))
        self.assertRaisesRegex(
            ValueError,
            "different program",
            prog.thread_from_object,
            Object(other_prog, "void *", 0x1000),
        )

    def test_thread_object_wrong_program(self):
        other_prog = Program(platform=Platform(Architecture.X86_64))

        class WrongProgramObjectThreadFinder(ThreadFinder):
            def thread(self, cache, tid):
                return cache.find_or_create(tid, 0)[0]

            def thread_object(self, thread):
                return Object(other_prog, "void *", 0x1000)

        prog = program_with_thread_finder(WrongProgramObjectThreadFinder())
        with self.assertRaisesRegex(ValueError, "different program"):
            prog.thread(1).object

    def test_finder_data(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        t1 = prog.thread(1)
        self.assertIsNone(t1._finder_data)
        data = object()
        t1._finder_data = data
        self.assertIs(prog.thread(1)._finder_data, data)

    def test_exceptions(self):
        prog = program_with_thread_finder(ExceptionThreadFinder())
        with self.assertRaisesRegex(TestException, "^threads$"):
            next(prog.threads())
        self.assertRaisesRegex(TestException, "^thread$", prog.thread, 2)
        self.assertRaisesRegex(TestException, "^main_thread$", prog.main_thread)
        self.assertRaisesRegex(TestException, "^crashed_thread$", prog.crashed_thread)
        thread = prog.thread(1)
        with self.assertRaisesRegex(TestException, "^thread_object$"):
            thread.object
        with self.assertRaisesRegex(TestException, "^thread_name$"):
            thread.name

    def test_register_only_one_enabled(self):
        prog = Program()
        prog.register_thread_finder("a", SimpleThreadFinder(), enable_index=0)
        self.assertRaises(
            ValueError,
            prog.register_thread_finder,
            "b",
            SimpleThreadFinder(),
            enable_index=0,
        )

    def test_set_enabled_only_one(self):
        prog = Program()
        prog.register_thread_finder("a", SimpleThreadFinder())
        prog.register_thread_finder("b", SimpleThreadFinder())
        self.assertRaises(ValueError, prog.set_enabled_thread_finders, ["a", "b"])

    def test_change(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        thread = prog.thread(1)

        prog.register_thread_finder("other", GenerationThreadFinder())
        prog.set_enabled_thread_finders(["other"])
        self.assertIsNot(prog.thread(1), thread)
        self.assertEqual(thread.tid, 1)

    def test_thread_cache(self):
        test_case = self

        class TestThreadCacheFinder(ThreadFinder):
            def thread(self, cache, tid):
                test_case.assertIsNone(cache.find(tid, 0))

                thread, new = cache.find_or_create(tid, 0)
                test_case.assertIsNotNone(thread)
                test_case.assertTrue(new)

                test_case.assertIs(cache.find(tid, 0), thread)

                thread2, new2 = cache.find_or_create(tid, 0)
                test_case.assertIs(thread2, thread)
                test_case.assertFalse(new2)

                return thread

        program_with_thread_finder(TestThreadCacheFinder()).thread(1)

    def test_thread_cache_generation(self):
        test_case = self

        class TestThreadCacheGenerationFinder(ThreadFinder):
            def thread(self, cache, tid):
                thread = cache.find_or_create(tid, 0)[0]

                test_case.assertIsNone(cache.find(tid, 1))
                thread2, new2 = cache.find_or_create(tid, 1)
                test_case.assertIsNot(thread2, thread)
                test_case.assertTrue(new2)

                return thread

        program_with_thread_finder(TestThreadCacheGenerationFinder()).thread(1)


class TestRegisterStateFinder(TestCase):
    def test_found(self):
        prog = program_with_thread_finder(SimpleThreadFinder())

        def thread_register_state(thread):
            regs = RegisterState(prog, interrupted=True)
            regs.pc = thread.tid * 0x1000
            return regs

        prog.register_register_state_finder(
            "test", thread_register_state, enable_index=0
        )

        self.assertEqual(prog.thread(2).register_state().pc, 0x2000)

    def test_not_found(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        prog.register_register_state_finder("test", lambda thread: None, enable_index=0)

        self.assertRaises(LookupError, prog.thread(2).register_state)

    def test_no_finder(self):
        prog = program_with_thread_finder(SimpleThreadFinder())

        self.assertRaises(LookupError, prog.thread(2).register_state)

    def test_multiple(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        prog.register_register_state_finder(
            "useless", lambda thread: None, enable_index=0
        )

        def thread_register_state(thread):
            if thread.tid != 2:
                return None
            regs = RegisterState(prog, interrupted=True)
            regs.pc = thread.tid * 0x1000
            return regs

        prog.register_register_state_finder(
            "test", thread_register_state, enable_index=1
        )

        def thread_register_state2(thread):
            regs = RegisterState(prog, interrupted=True)
            regs.pc = thread.tid * 0x1111
            return regs

        prog.register_register_state_finder(
            "test2", thread_register_state2, enable_index=2
        )

        self.assertEqual(prog.thread(1).register_state().pc, 0x1111)
        self.assertEqual(prog.thread(2).register_state().pc, 0x2000)

    def test_error(self):
        prog = program_with_thread_finder(SimpleThreadFinder())

        prog.register_register_state_finder(
            "error", lambda thread: 1 / 0, enable_index=0
        )

        def thread_register_state(thread):
            regs = RegisterState(prog, interrupted=True)
            regs.pc = thread.tid * 0x1000
            return regs

        prog.register_register_state_finder(
            "test", thread_register_state, enable_index=1
        )

        self.assertRaises(ZeroDivisionError, prog.thread(2).register_state)

    def test_wrong_return_type(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        prog.register_register_state_finder(
            "test", lambda thread: "foo", enable_index=0
        )

        self.assertRaises(TypeError, prog.thread(2).register_state)

    def test_wrong_program(self):
        prog = program_with_thread_finder(SimpleThreadFinder())
        other_prog = Program(platform=Platform(Architecture.X86_64))

        def thread_register_state(thread):
            return RegisterState(other_prog, interrupted=True)

        prog.register_register_state_finder(
            "test", thread_register_state, enable_index=0
        )

        self.assertRaisesRegex(
            ValueError, "different program", prog.thread(2).register_state
        )
