import glob
import os
import subprocess
import difflib
import sys

exectedOutputDir = "ExpectedOutputs/"


def main():
    # Make everything relative to our location.
    ourLocation = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ourLocation)

    # run make on all programs.
    subprocess.call(["make"])
    allSame = True

    for cProgram in glob.glob("*.c"):
        prog = cProgram.split(".")[0]

        # Call program under dettrace!
        try:
            print("========= Testing \"{}\"=========".format(prog))
            output = runProgram(prog)

            # Read reference version from file.
            if prog == "callSshKeygen" :
                # Call program twice instead of using file
                compare = runProgram(prog)
            else:
                compare = open(exectedOutputDir + prog + ".output", "r").read()

            # Compare
            if(output != compare):
                print("Failure\n")
                # Failed diff, find difference.
                allSame = False

                # print raw output, useful for constructing expected output for failing tests
                #sys.stdout.write("{"+output+"}")

                print("File diff:")
                diff = difflib.ndiff(output.splitlines(keepends=True),
                                     compare.splitlines(keepends=True))
                print(''.join(diff), end="")

            else:
                print("Success\n")

        except subprocess.CalledProcessError as e:
            print("Program failed to run!)")
        except IOError:
            print("Failed to open file: {}".format(exectedOutputDir + prog))

    if not allSame:
        exit(1)
    else:
        exit(0)

def runProgram(prog):
    # Run and get output in this machine.
    try:
        outputBin = subprocess.check_output(["../../bin/dettrace", "./" + prog], \
                                            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as cpe:
        # sometimes test "failures" are expected, e.g., with system calls we don't handle
        outputBin = cpe.output
    # From binary to string.
    return outputBin.decode(encoding='UTF-8')

if __name__ == "__main__":
    main()
