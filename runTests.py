import glob
import os
import subprocess

def main():
    # Make everything relative to our location.
    ourLocation = os.path.dirname(os.path.abspath(__file__))
    os.chdir(ourLocation)

    # Assure we're using the latest build.
    print("Building program!")
    subprocess.check_call(["make"])

    # Run unit tests.
    print("Running unit tests.")
    unitTestsCommand = ["./bin/dettrace", "./test/unitTests/systemCallTests"]
    subprocess.check_call(unitTestsCommand)
    # Catch doesn't return a non-zero error code on failure. We slurp up the output
    # and check for failure ourselves.
    try:
        outputBin = subprocess.check_output(unitTestsCommand)
        if "FAILED" in outputBin.decode("utf-8"):
            print("Failure!")
            exit(1)
    except subprocess.CalledProcessError as e:
        print("Failure!")
        exit(1)

    # Run sample programs, compare output.
    subprocess.check_call(["python3", "./test/samplePrograms/compareOutputs.py"])

    print("All tests PASSED")
    exit(0)

if __name__ == "__main__":
    main()
