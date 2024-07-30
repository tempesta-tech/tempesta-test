import datetime
import os
import time
import subprocess
import signal
import argparse
import shutil

class Logger():
    def __run_tcpdump(self, ethname) -> None:
        """
        Run `tcpdump` before the test if `-s` (--save-tcpdump) option is used.
        Save result in a <name>.pcap file, where <name> is name of test.
        """
        path = f"/var/tcpdump/{datetime.date.today()}"
        file_name = datetime.datetime.now().strftime('%H:%M:%S')

        if not os.path.isdir(path):
            os.makedirs(path)
        self.__tcpdump = subprocess.Popen(
            [
                "tcpdump",
                "-U",
                "-i",
                f"{ethname}",
                "-w",
                f"{path}/{file_name}.pcap",
            ],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def __clear_tcpdump_files(self, directory, cur_time, time_to_clear_dump) -> None:
        for _f in os.listdir(directory):
            f = os.path.join(directory, _f)
            t = os.path.getctime(f)
            if cur_time - t > time_to_clear_dump:
                os.remove(f)

    def __clear_tcpdump(self, cur_time, time_to_clear_dump) -> None:
        path = f"/var/tcpdump/"
        directory = os.fsencode(path)

        for _d in os.listdir(directory):
            d = os.path.join(directory, _d)
            if d.decode('UTF-8') != f"/var/tcpdump/{datetime.date.today()}":
                shutil.rmtree(d)
            else:
                self.__clear_tcpdump_files(d, cur_time, time_to_clear_dump)

    def __stop_tcpdump(self) -> None:
        """
        Stop tcpdump.
        `wait()` always causes `TimeoutExpired` error because `tcpdump` cannot terminate on
        its own. But it requires a timeout to flush data from buffer.
        """
        try:
            self.__tcpdump.send_signal(signal.SIGUSR2)
            self.__tcpdump.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.__tcpdump.kill()
            self.__tcpdump.wait()

        self.__tcpdump = None

    def run(self, ethname, time_to_new_dump=3600, time_to_clear_dump=21600) -> None:
        t0 = time.time()
        self.__run_tcpdump(ethname)

        while True:
            t = time.time()
            self.__clear_tcpdump(t, time_to_clear_dump)
            if t - t0 > time_to_new_dump:
                self.__stop_tcpdump()
                self.__run_tcpdump(ethname)
                t0 = t
            time.sleep(time_to_new_dump / 10 if time_to_new_dump > 10 else 1)

parser = argparse.ArgumentParser()
parser.add_argument("-e", "--ethname", type=str)
parser.add_argument("-tn", "--time-to-new-dump", type=int)
parser.add_argument("-tc", "--time-to-clear-dump", type=int)
args = parser.parse_args()

Log = Logger()
Log.run(args.ethname, args.time_to_new_dump, args.time_to_clear_dump)

