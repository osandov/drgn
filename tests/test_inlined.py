import subprocess
import tempfile

from drgn import Program
from tests import TestCase


class TestInlinedFunctions(TestCase):
    def test_inlined_functions(self):
        with tempfile.NamedTemporaryFile() as executable, tempfile.NamedTemporaryFile(
            mode="w"
        ) as program:
            executable.close()
            program.write(
                """
                #include <unistd.h>

                int __attribute__((noinline)) function_three(int x) {
                    return x + 2;
                }

                static inline int __attribute__((always_inline)) function_one(int x) {
                    return (x * 3) + (x >> 7);
                }

                static inline int __attribute__((always_inline)) function_two(int x) {
                    return (x / 6) - (x % 14);
                }

                int main(int argc, char* argv[]) {
                    pause();
                    argc = function_three(argc);
                    if (argc % 2 == 0)
                        return function_one(argc * 3) + function_two(argc / 99);
                    else
                        return function_one(argc + 2 + (argc / 5)) * function_two(argc - 83);
                }
                """
            )
            program.flush()
            subprocess.check_call(
                (
                    "clang++",
                    "-x",
                    "c++",
                    "-Wall",
                    "-Werror",
                    "-g",
                    "-O3",
                    "-o",
                    executable.name,
                    program.name,
                )
            )
            prog = Program()
            try:
                process = subprocess.Popen([executable.name])
                prog.set_pid(process.pid)
                prog.load_debug_info([executable.name])
                inlined_functions = list(prog.inlined_functions())
                self.assertEqual(2, len(inlined_functions))
                for group in inlined_functions:
                    self.assertIn(group.name, ("function_one", "function_two"))
                    self.assertIn("function", group.linkage_name)
                    self.assertEqual(2, len(group.inlined_instances))
                    for instance in group.inlined_instances:
                        # Make sure these aren't 0 (i.e. NULL)
                        self.assertTrue(instance.die_addr)
                        self.assertTrue(instance.entry_pc)
            finally:
                process.terminate()
                process.wait()
