#!/usr/bin/env python

## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Usage: ./timeout.py TIMEOUT COMMAND...

This is a shell script that runs a command for up to TIMEOUT (expressed in
seconds, minutes or hours), sending the command a SIGKILL once the timeout
expires.  If the command exits sooner, then this script will exit as well.

This functionality is also exposed as a Python module. The TimerTask class
handles running a command in a child process.  There are many modules in the
Python standard library that do this, however.  Here's what's different about
TimerTask:

You can set a timeout such that TimerTask.wait() returns when either 1) the
child process exits naturally or 2) the timeout expires and the child process
receives a specified signal causing it to terminate.  TimerTask.wait() returns
whenever the *sooner* of 1) or 2) happens.

TimerTask uses the SIGALRM signal for its timeout, and so will interfere with
programs that need SIGALRM for other purposes. If you do not specify the use of
a timeout, however, no signal handling will be used.

Finally, the child process is, by default, run in its own process group, to make
it easier to clean up the child process along with any other processes it may
have spawned.
"""

import errno,os,signal,subprocess,sys

class TimerTask:
    def __init__( self, command, timeout=None, 
                  timeoutSignal=signal.SIGKILL, raisePrevSigalrmError=True,
                  childProcessGroup=0 ):
        """Create a new TimerTask
command : string : the command to run
timeout : int : timeout (in seconds), or None for no timeout (default: None)
signal : int : the signal to send to the child process at timeout (default: SIGKILL)
raisePrevSigalrmError : bool : if True, throw an exception if there's
  a previous non-nop SIGALRM handler installed (default: True)
childProcessGroup : int : if 0 (default), put child process into its own process group
  if non-zero, put child process into the specified process group
  if None, inherit the parent's process group
"""
        assert isinstance( command, str ) or isinstance( command, list )
        self.command = command

        if timeout is not None:
            assert isinstance( timeout, int )
            assert timeout > 0
        self.timeout = timeout
        
        assert isinstance( timeoutSignal, int )
        self.timeoutSignal = timeoutSignal

        self.prevAlarmHandler = None
        self.raisePrevSigalrmError = raisePrevSigalrmError

        if None == childProcessGroup:
            self.preExecFun = None
        else:
            assert isinstance( childProcessGroup, int )
            self.preExecFun = (lambda : os.setpgid(0,childProcessGroup))
                

    def run( self, 
             stdin=None, stdout=None, stderr=None, 
             shell=True, cwd=None, env=None ):
        """Takes the same arguments as Python's subprocess.Popen(), with the
following exceptions:

1. this version runs the command in a shell by default (shell=True)
2. this function needs the preexec_fn hook, so that is not available

This function returns the result from subprocess.Popen() (a subprocess
object), so you can read from pipes, poll, etc.
"""

        self.subprocess = subprocess.Popen( self.command,
                                            stdin=stdin, 
                                            stdout=stdout,
                                            stderr=stderr,

                                            # runs in the child
                                            # process before
                                            # the exec(), putting
                                            # the child process into
                                            # its own process group
                                            preexec_fn=self.preExecFun,

                                            shell=shell,
                                            cwd=cwd,
                                            env=env )
        self.pgid = os.getpgid( self.subprocess.pid )

        # Setup the SIGALRM handler: we use a lambda as a "curried"
        # function to bind some values
        if self.timeout is not None:

            if signal.getsignal( signal.SIGALRM ) not in (None, signal.SIG_IGN, signal.SIG_DFL):
                # someone is using a SIGALRM handler!
                if self.raisePrevSigalrmError:
                    ValueError( "SIGALRM handler already in use!" )

            self.prevAlarmHandler = signal.getsignal( signal.SIGALRM )

            signal.signal( signal.SIGALRM, 
                           lambda sig,frame : os.killpg(self.pgid,self.timeoutSignal) )

            # setup handler before scheduling signal, to eliminate a race
            signal.alarm( self.timeout )

        return self.subprocess

    def cancelTimeout(self):
        """If we're using a timeout, cancel the SIGALRM timeout when
           the child is finished, and restore the previous SIGALRM handler"""
        if self.timeout is not None:
            signal.alarm( 0 )
            signal.signal( signal.SIGALRM, self.prevAlarmHandler )
            pass
        return

    def wait(self):
        """Wait for the child process to exit, or the timeout to expire,
whichever comes first.  

This function returns the same thing as Python's
subprocess.wait(). That is, this function returns the exit status of
the child process; if the return value is -N, it indicates that the
child was killed by signal N. """

        try:
            self.subprocess.wait()
        except OSError, e:
            
            # If the child times out, the wait() syscall can get
            # interrupted by the SIGALRM. We should then only need to
            # wait() once more for the child to actually exit.
            
            if e.errno == errno.EINTR:
                self.subprocess.wait()
            else:
                raise e
            pass

        self.cancelTimeout()

        assert self.subprocess.poll() is not None
        return self.subprocess.poll()


    def kill(self, deathsig=signal.SIGKILL):
        """Kill the child process. Optionally specify the signal to be used
(default: SIGKILL)"""
        try:
            os.killpg( self.pgid, deathsig )
        except OSError, e:
            if e.errno == errno.ESRCH:
                # We end up here if the process group has already exited, so it's safe to
                # ignore the error
                pass
            else:
                raise e
            pass

        self.cancelTimeout()


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print "Usage:", sys.argv[0], "TIMEOUT COMMAND..."
        print

        descrip = """Runs COMMAND for up to TIMEOUT, sending COMMAND a SIGKILL if it
attempts to run longer. Exits sooner if COMMAND does so, passing along COMMAND's
exit code. TIMEOUT is of the form 12s, 12m or 12h for a timeout of 12 seconds,
minutes or hours, respectively.

All of COMMAND's children run in a new process group, and the entire group is
SIGKILL'ed when the timeout expires. """
        print descrip

        sys.exit( 1 )
        pass

    # parse the timeout
    
    timeoutString = sys.argv[1]
    units = timeoutString[-1]
    if units not in ['s','m','h']:
        print "Invalid timeout units (should be one of s, m, or h): ", timeoutString
        sys.exit( 1 )
        pass
    duration = None
    try:
        duration = int(timeoutString[:-1])
    except ValueError:
        print "Invalid timeout value (should be a number): ", timeoutString
        sys.exit( 1 )
        pass

    if units == 's':
        pass
    elif units == 'm':
        duration *= 60
    elif units == 'h':
        duration *= 60 * 60
        pass
    
    # launch the task
    t = TimerTask( " ".join(sys.argv[2:]),
                   timeout=duration )
    t.run()
    e = t.wait()
    sys.exit( e )


