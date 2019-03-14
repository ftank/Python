#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import re
import gzip


# Colors Output
class Colors:
    BOLD = "\033[1m"
    ENDC = '\033[0m'
    WHITE = '\033[37m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'

# creating global colors variable
COLORS = Colors()

localpath = "/data/home/moo/"
resultfile = open(localpath + 'resultfile.txt', 'w+')
resultfile.close()
os.remove(localpath + 'resultfile.txt')


###
### ANALYSE DEADLOCKS
###

def analyse_deadlock(path2):
    dlfile = []
    local_analyzer = "/data/home/moo/introproSRC/showThreadsAndLocks.py "
    for filename in os.listdir(path2):
        if re.match("kill" or "0_watchdog", filename):
            dlfile.append(filename)

    for l in range(len(dlfile)):
        if re.match("kill-3_output.txt.gz", dlfile[l]):
            inF = gzip.GzipFile(path2 + "kill-3_output.txt.gz", 'rb')
            s = inF.read()
            inF.close()

            outF = file(path2 + "kill-3_output.txt", 'wb')
            outF.write(s)
            outF.close()
            print (COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  " + dlfile[l] + " dump stack file was found" + COLORS.ENDC)
            readkey = raw_input(
                COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Display showThreadsAndLocks.py analysis of " + dlfile[
                    l] + "? [y/n]" + COLORS.ENDC)
            if readkey == 'y':
                command = local_analyzer + path2 + "kill-3_output.txt"
                os.system(command)
                print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  End of Log Analyser" + COLORS.ENDC)
                exit()

        elif dlfile[l].endswith(".txt"):
            print (COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  " + dlfile[l] + " dump stack file was found" + COLORS.ENDC)
            readkey = raw_input(
                COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Display showThreadsAndLocks.py analysis of " + dlfile[
                    l] + "? [y/n]" + COLORS.ENDC)
            if readkey == 'y':
                command = local_analyzer + path2 + dlfile[l]
                os.system(command)
        elif '0_watchdog' in dlfile[l]:
            print (COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  " + dlfile[l] + " dump stack file was found" + COLORS.ENDC)
            print (COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Display showThreadsAndLocks.py analysis of " + dlfile[
                l] + "? [y/n]" + COLORS.ENDC)
            readkey = raw_input(COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Display error messages after siege crash? [y/n]")
            if readkey == 'y':
                os.system(local_analyzer, + path2 + dlfile[l])
            else:
                print ("y not pressed!!")

        else:
            print(COLORS.YELLOW + COLORS.BOLD + "                                     !!! WARNING !!!" + COLORS.ENDC)
            print(
                    COLORS.YELLOW + "=====>>>>>  STB had deadlock reported in logs, but kill-3_output.txt or 0_watchdog*.txt dump stack files are missing!" + COLORS.ENDC)
            print(COLORS.YELLOW + "=====>>>>>  Please check manually !!" + COLORS.ENDC)


###
### ANALYSE SIEGE CORE
###

def analyse_siegecore(path2):
    for filename in os.listdir(path2):
        if re.match("core.siege.\d+$", filename):
            command = `"cd /var/viewer; touch /var/viewer/c_gdb; echo 'bt' > /var/viewer/c_gdb; /var/viewer/gdb -x /var/viewer/c_gdb -batch /opt/vm/siege /var/viewer/"` + filename
            match = []
            for l in range(17):
                match.append("STB_" + str(l))
                if match[l] in path2:
                    print (COLORS.YELLOW + COLORS.BOLD + "=====>>>>> " + filename + " was found on " + match[
                        l] + COLORS.ENDC)
                    readkey = raw_input(
                        COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Do you want to see siege crash backtrace? [y/n]" + COLORS.ENDC)
                    if readkey == 'y':
                        os.system("/data/home/moo/introproSRC/run_on_stb.sh " + str(l) + ' ' + command)
                        print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  End of Log Analyser" + COLORS.ENDC)
                        exit()

                    else:
                        print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  End of Log Analyser" + COLORS.ENDC)
                        exit()


###
### ANALYSE DVR_CORE
###

def analyse_dvrcore(path2):
    for filename in os.listdir(path2):
        if re.match("core.dvr_core.\d+$", filename):
            command = `"cd /var/viewer; touch /var/viewer/c_gdb; echo 'bt' > /var/viewer/c_gdb; /var/viewer/gdb -x /var/viewer/c_gdb -batch /opt/vm/siege /var/viewer/"` + filename
            match = []
            for l in range(17):
                match.append("STB_" + str(l))
                if match[l] in path2:
                    print (COLORS.YELLOW + COLORS.BOLD + "=====>>>>> " + filename + " was found on " + match[
                        l] + COLORS.ENDC)
                    readkey = raw_input(
                        COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Do you want to see dvr_core crash backtrace? [y/n]" + COLORS.ENDC)
                    if readkey == 'y':
                        os.system("/data/home/moo/introproSRC/run_on_stb.sh " + str(l) + ' ' + command)
                        print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  End of Log Analyser" + COLORS.ENDC)
                        exit()

                    else:
                        print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  End of Log Analyser" + COLORS.ENDC)
                        exit()


###
### FILTER LOGS
###


def filter_logs(path2, nc):
    words = ["ASSERT FAILED", "DEADLOCK", "WATCHDOG", "DVR_CORE DEADLOCK", "Memory completely exhausted",
             "OutOfMemoryError", "Out of memory", "Memory thresholds were broken too much", "oom-killer",
             "mtdoops_reader", "L2fatal", "INTERNAL ERROR", "FORCE_ABORT", "klogd", "eXtremeDB Fusion",
             "ERR NEXUS_DspVideoEncoder_P_Watchdog_isr", "THRESHOLD is broken",
             "CaMgrOutgoingMsgDispatcher::addRequest trail indicates CaMgrDataToIrdMsg", "### Error at", "!!!Error"]
    for filename in sorted(os.listdir(path2), key=lambda x: x[-3:]):
        if re.match('message', filename):
            with open(path2 + filename, 'r') as log_file:
                logs = log_file.readlines()
                for line in logs:
                    for word in words:
                        if word in line:
                            results = open(localpath + "resultfile.txt", "a")
                            results.write('%s: %s' % (filename, line))

    if nc == '-nc':
        filter_no_comments()
    else:
        filter_final_result_arrays(path2)
        # filter_final_result()


###
### NO COMMENTS OPTION
###

def filter_no_comments():
    with open(localpath + "resultfile.txt", "r") as results:
        final = results.readlines()
        for line in final:
            print(line).strip()


###
### Filtering and Showing the results
###

def filter_final_result_arrays(path2):
    with open(localpath + "resultfile.txt", "r") as results:
        final = results.readlines()
        assert_failed = []
        dvr_core_dl = []
        dl = []
        dtv_wd_siege_dl = []
        dtv_wd_reboot = []
        omm_killer = []
        mce = []
        membroken = []
        klogd = []
        mtdoops = []
        forceabon = []
        force_abort = []
        joom = []

        for line in final:
            if "ASSERT FAILED" in line:
                assert_failed.append(line)
            if "DVR_CORE DEADLOCK" in line:
                dvr_core_dl.append(line)
            if "!DEADLOCK!" in line:
                dl.append(line)
            if "DTV_WATCHDOG_SIEGE_DEADLOCK: (SMT)Deadlock detected" in line:
                dtv_wd_siege_dl.append(line)
            if "DTV_WATCHDOG_REBOOT" in line:
                dtv_wd_reboot.append(line)
            if "oom-killer" in line:
                omm_killer.append(line)
            if "Memory completely exhausted" in line:
                mce.append(line)
            if "Memory thresholds were broken too much" in line:
                membroken.append(line)
            if "OutOfMemoryError" in line:
                joom.append(line)
            if "kernel" in line:
                klogd.append(line)
            if "kill-3_output.txt" in line:
                trace_kill3 = True
            if "mtdoops_reader" in line:
                mtdoops.append(line)
                mtdoopsa = True
            if "forcing abort on" in line:
                forceabon.append(line)
            if "FORCE_ABORT" in line:

                if "siege" in line:
                    force_abort.append(line)
                if "dvr_core" in line:
                    force_abort.append(line)
        print (
                COLORS.YELLOW + COLORS.BOLD + "                                  !!! STB BOOTUP STARTED !!!" + COLORS.ENDC)
        print (
                COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  If this happened in the middle of stressrun it means that STB rebooted" + COLORS.ENDC)
        for l in range(len(klogd)):
            print (COLORS.WHITE + klogd[l].strip() + COLORS.ENDC)
        if len(assert_failed) > 0:
            print (COLORS.RED + "=====>>>>>  ASSERT FAILED will usually result siege crash" + COLORS.ENDC)
            for l in range(len(assert_failed)):
                print (COLORS.WHITE + COLORS.BOLD + assert_failed[l].strip() + COLORS.ENDC)
        if len(dtv_wd_siege_dl) > 0:
            print (COLORS.RED + COLORS.BOLD + "=====>>>>>  WATCHDOG have found DEADLOCK" + COLORS.ENDC)
            print (COLORS.RED + COLORS.BOLD + "=====>>>>>  This is full siege deadlock" + COLORS.ENDC)
            for l in range(len(dtv_wd_siege_dl)):
                print (COLORS.WHITE + dtv_wd_siege_dl[l].strip() + COLORS.ENDC)
        if len(omm_killer) > 0:
            print (
                    COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  oom-killer was invoked and stb is probably dead after that" + COLORS.ENDC)
            for l in range(len(omm_killer)):
                print (COLORS.WHITE + omm_killer[l].strip() + COLORS.ENDC)
        if len(mce) > 0:
            print (
                    COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Java Memory state is really bad at this point" + COLORS.ENDC)
            for l in range(len(mce)):
                print (COLORS.WHITE + mce[l].strip() + COLORS.ENDC)
        if len(joom) > 0:
            print (COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Java out Memory Error !!! " + COLORS.ENDC)
            for l in range(len(joom)):
                print (COLORS.WHITE + joom[l].strip() + COLORS.ENDC)
        if len(membroken) > 0:
            print (
                    COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  MemoryLeaksDetector wants to reboot STB because of broken memory threshold" + COLORS.ENDC)
            for l in range(len(membroken)):
                print(COLORS.WHITE + membroken[l].strip() + COLORS.ENDC)
        if len(dl) > 0:
            if len(dl) == 1:
                print (COLORS.WHITE + COLORS.BOLD + "=====>>>>>  NO DEADLOCKS FOUND" + COLORS.ENDC)
            else:
                print (COLORS.RED + COLORS.BOLD + "=====>>>>>  DeadlockDetector have found DEADLOCK" + COLORS.ENDC)
                print (
                        COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  This can be temporary or full deadlock depending on consequenses" + COLORS.ENDC)
                for l in range(len(dl)):
                    print (COLORS.WHITE + dl[l].strip())

        if len(dvr_core_dl) > 0:
            print (
                    COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  DVR_CORE DEADLOCKs can be major or minor issues depending on consequences" + COLORS.ENDC)
            for l in range(len(dvr_core_dl)):
                print(COLORS.WHITE + dvr_core_dl[l].strip() + COLORS.ENDC)
        if len(dtv_wd_reboot) > 0:
            print (
                    COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  WATCHDOG thinks that STB is dead and wants to reboot STB!" + COLORS.ENDC)
            print(COLORS.WHITE + dtv_wd_reboot[-5].strip() + COLORS.ENDC)
            print(COLORS.WHITE + dtv_wd_reboot[-4].strip() + COLORS.ENDC)
            print(COLORS.WHITE + dtv_wd_reboot[-3].strip() + COLORS.ENDC)
            print(COLORS.WHITE + dtv_wd_reboot[-2].strip() + COLORS.ENDC)
            print(COLORS.WHITE + dtv_wd_reboot[-1].strip() + COLORS.ENDC)
        if len(forceabon) > 0:
            print(COLORS.RED + COLORS.BOLD + "                              !!! WARNING !!!" + COLORS.ENDC)
            if "siege" in forceabon[-1]:
                print(COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  Siege is going to be aborted!" + COLORS.ENDC)
                for l in range(len(forceabon)):
                    print(COLORS.WHITE + forceabon[l].strip())
            if "dvr_core" in forceabon[-1]:
                print(COLORS.YELLOW + COLORS.BOLD + "=====>>>>>  dvr_core is going to be aborted!" + COLORS.ENDC)
                for l in range(len(forceabon)):
                    print(COLORS.WHITE + forceabon[l].strip())
        if len(force_abort) > 0:
            print(COLORS.RED + COLORS.BOLD + "=====>>>>>  CORE FILE IS DETECTED" + COLORS.ENDC)
            print(COLORS.WHITE + force_abort[-3].strip())
            print(COLORS.WHITE + force_abort[-2].strip())
            print(COLORS.WHITE + force_abort[-1].strip())
            if "siege" in force_abort[-1]:
                siegecore = True
                print(
                        COLORS.RED + COLORS.BOLD + "                          !!! SIEGE CORE FILE IS DETECTED !!!" + COLORS.ENDC)
                print(" ")

                if siegecore == True:
                    analyse_siegecore(path2)

                if len(dl) > 3:
                    analyse_deadlock(path2)
                else:
                    print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  End of Log Analyser" + COLORS.ENDC)
                    exit()

            if "dvr_core" in force_abort[-1]:
                dvrcore = True
                print(
                        COLORS.RED + COLORS.BOLD + "                          !!! DVR_CORE CORE FILE IS DETECTED !!!" + COLORS.ENDC)
                if dvrcore == True:
                    analyse_dvrcore(path2)

                if len(dl) > 3:
                    analyse_deadlock(path2)

            else:
                print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  End of Log Analyser" + COLORS.ENDC)
                exit()


# HELP of the Script
def print_help():
    print ("Usage: logs_analyser.py <log folder> [-options]")
    print ("Script greps getter log folder for error messages and outputs them in chronological order.")
    print ("Messages are parced to improve readability of output.")
    print ("Deadlock stack traces are analyzed using showThreadsAndLocks.py script")
    print ("Siege cores are analyzed using gdb on STB")
    print (" ")
    print ("Options")
    print ("-nc :")
    print ("")
    print ("Print output without comments, good for copy-pasting to Jira ticket")
    print ("Deadlock bactrace and siege core analysys is disabled when using -nc option")


def main(argv):
    args = sys.argv[1:]
    path = os.path.isdir(args[0])
    path2 = args[0]
    if len(args) == 2:
        nc = args[1]
        filter_logs(path2, nc)
    elif len(args) == 1:
        if args[0] == '-h':
            print (print_help())
            exit()
        elif path == True:
            print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  Starting Log Analyser !!!" + COLORS.ENDC)
            print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  Analyzing logs in " + COLORS.WHITE + path2)
            print (COLORS.GREEN + COLORS.BOLD + "=====>>>>>  It will take some minutes, please wait...")
            nc = 'anything'
            filter_logs(path2, nc)
        elif path == False:
            print (COLORS.RED + COLORS.BOLD + '!!! Directory NOT found !!!' + COLORS.ENDC)
    else:
        print (COLORS.WHITE + COLORS.BOLD + 'USAGE: logs_analyser.py <PATH OF LOGS>' + COLORS.ENDC)
        print (COLORS.WHITE + COLORS.BOLD + 'For more details type: logs_analyser.py -h' + COLORS.ENDC)
        exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
