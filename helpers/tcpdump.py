import datetime
import os
import time
import subprocess
import signal
import argparse
import shutil


class Logger:
    def __run_tcpdump(
        self, ethname, file_size, file_count, file_name, ports, src, dst, direction
    ) -> None:
        """
        Save result in a <file_name>.pcap file.
        """
        path = f"/var/tcpdump/{datetime.date.today()}"

        if not os.path.isdir(path):
            os.makedirs(path)

        args = [
            "tcpdump",
            "-U",
            "-i",
            f"{ethname}",
            "-C",
            f"{file_size}",
            "-W",
            f"{file_count}",
            "-w",
            f"{path}/{file_name}-{direction}.pcap",
            "-Q",
            f"{direction}",
            "-Z",
            "root",
        ]

        if ports:
            args += ["port"]
            args += [f"{ports[0]}"]

            for i in range(1, len(ports)):
                args += ["and"]
                args += ["port"]
                args += [f"{ports[i]}"]

        if src:
            args += [f"ip src {src}"]
        if dst:
            args += [f"ip dst {dst}"]

        if direction == "in":
            self.__tcpdump_in = subprocess.Popen(
                args=args,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        elif direction == "out":
            self.__tcpdump_out = subprocess.Popen(
                args=args,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            print("Fail to start tcpdump - invalid direction")
            return

    def __stop_tcpdump(self, direction) -> None:
        """
        Stop tcpdump.
        `wait()` should never causes `TimeoutExpired` error because `tcpdump` can
        be successfully terminate by SIGINT. But it requires a timeout to flush
        data from buffer.
        """

        __tcpdump = None
        if direction == "in":
            __tcpdump = self.__tcpdump_in
        elif direction == "out":
            __tcpdump = self.__tcpdump_out
        else:
            print("Fail to stop tcpdump - invalid direction")
            return

        try:
            __tcpdump.send_signal(signal.SIGINT)
            __tcpdump.wait(timeout=3)
        except subprocess.TimeoutExpired:
            __tcpdump.kill()
            __tcpdump.wait()

        if direction == "in":
            self.__tcpdump_in = None
        elif direction == "out":
            self.__tcpdump_out = None

    def run(
        self,
        ethname=None,
        exec_time=None,
        file_size=None,
        file_count=None,
        file_name=None,
        ports=None,
        src=None,
        dst=None,
    ) -> None:
        ethname = ethname if ethname else "lo"
        exec_time = exec_time if exec_time else 60
        file_size = file_size if file_size else 50
        file_count = file_count if file_count else 10
        file_name = file_name if file_name else f"{datetime.datetime.now().strftime('%H:%M:%S')}"

        self.__run_tcpdump(ethname, file_size, file_count, file_name, ports, src, dst, "in")
        self.__run_tcpdump(ethname, file_size, file_count, file_name, ports, src, dst, "out")
        time.sleep(exec_time * 60)
        self.__stop_tcpdump("in")
        self.__stop_tcpdump("out")


parser = argparse.ArgumentParser()
parser.add_argument("-e", "--ethname", type=str)
parser.add_argument("-t", "--exec-time", type=int)
parser.add_argument("-s", "--file-size", type=int)
parser.add_argument("-c", "--file-count", type=int)
parser.add_argument("-n", "--file-name", type=str)
parser.add_argument("-p", "--port", action="append", type=int)
parser.add_argument("--src", type=str)
parser.add_argument("--dst", type=str)

args = parser.parse_args()

Log = Logger()
Log.run(
    args.ethname,
    exec_time=args.exec_time,
    file_size=args.file_size,
    file_count=args.file_count,
    file_name=args.file_name,
    ports=args.port,
    src=args.src,
    dst=args.dst,
)
