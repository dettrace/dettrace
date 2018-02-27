import glob
import os
import subprocess

def main():
    # Make everything relative to our location.
    ourLocation = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ourLocation)

    # Assure we're using the latest build.
    print("Building program!")
    ret = subprocess.call(["make"])
    if ret != 0:
        print("Failure!")
        exit(1)

    # Run unit tests.
    print("Running unit tests.")
    ret = subprocess.call(["./bin/dettrace", "./test/unitTests/systemCallTests"])
    # Catch doesn't return a non-zero error code on failure. We slup up the output
    # and check for failure ourselves.
    try:
        outputBin = \
          subprocess.check_output(["./bin/dettrace", "./test/unitTests/systemCallTests"])
        if "FAILED" in outputBin.decode("utf-8"):
            print("Failure!")
            exit(1)
    except subprocess.CalledProcessError as e:
        # Let CI know we failed.
        if ret != 0:
            print("Failure!")
            exit(1)

    # Run sample programs, compare output.
    ret = subprocess.call(["python3", "./test/samplePrograms/compareOutputs.py"])
    if ret != 0:
        print("Failure!")
        exit(1)

    print("All tests PASSED")
    exit(0)

if __name__ == "__main__":
    main()
