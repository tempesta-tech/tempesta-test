import argparse
import datetime
import os
import shutil
import signal
import subprocess
import time


class Logger:
    def __add_ports(self, ports, args):
        if ports:
            args += ["tcp port"]
            args += [f"{ports[0]}"]

            for i in range(1, len(ports)):
                args += ["or"]
                args += ["tcp port"]
                args += [f"{ports[i]}"]

    def __add_ip(self, ip, direction, args):
        if ip:
            args += [f"ip {direction}"]
            args += [f"{ip[0]}"]

            for i in range(1, len(ip)):
                args += ["or"]
                args += [f"ip {direction}"]
                args += [f"{ip[i]}"]

    def __run_tcpdump(
        self, ethname, file_size, file_count, file_name, src_ports, dst_ports, src, dst, direction
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

        combine = src_ports and dst_ports
        self.__add_ports(src_ports, args)
        if combine:
            args += ["or"]
        self.__add_ports(dst_ports, args)

        if (src_ports or dst_ports) and (src or dst):
            args += ["and"]

        combine = src and dst
        self.__add_ip(src, "src", args)
        if combine:
            args += ["or"]
        self.__add_ip(dst, "dst", args)

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
        src_ports=None,
        dst_ports=None,
        src=None,
        dst=None,
        direction=None,
    ) -> None:
        ethname = ethname if ethname else "lo"
        exec_time = exec_time if exec_time else 60
        file_size = file_size if file_size else 50
        file_count = file_count if file_count else 10
        file_name = file_name if file_name else f"{datetime.datetime.now().strftime('%H:%M:%S')}"
        direction = direction if direction else ["in", "out"]

        if "in" in direction:
            self.__run_tcpdump(
                ethname, file_size, file_count, file_name, src_ports, dst_ports, src, dst, "in"
            )
        if "out" in direction:
            self.__run_tcpdump(
                ethname, file_size, file_count, file_name, src_ports, dst_ports, src, dst, "out"
            )
        if (not "in" in direction) and (not "out" in direction):
            print("Invalid direction, (in|out) supported")
            return

        time.sleep(exec_time * 60)
        self.__stop_tcpdump("in")
        self.__stop_tcpdump("out")


parser = argparse.ArgumentParser()
parser.add_argument("-e", "--ethname", type=str, help="Device name to capture packets.")
parser.add_argument(
    "-t", "--exec-time", type=int, help="Execution time in minutes (60 by default)."
)
parser.add_argument(
    "-s",
    "--file-size",
    type=int,
    help="Dump file size in megabytes (50 by default). When size is exceeded new file will be created.",
)
parser.add_argument(
    "-c",
    "--file-count",
    type=int,
    help="Count of dump files (10 by default). When count is exceeded new file overwrite old file.",
)
parser.add_argument(
    "-n", "--file-name", type=str, help="Dump file name (current time in H:M:S by default)."
)
parser.add_argument(
    "-ps",
    "--src-port",
    action="append",
    type=int,
    help="Source ports, used in tcpdump filtration (empty by default, dump for all ports).",
)
parser.add_argument(
    "-pd",
    "--dst-port",
    action="append",
    type=int,
    help="Destination ports, used in tcpdump filtration (empty by default, dump for all ports).",
)
parser.add_argument(
    "--src",
    type=str,
    help="Source ip addresses, used in tcpdump filtration (empty by default, dump for all source ip).",
    action="append",
)
parser.add_argument(
    "--dst",
    type=str,
    help="Destination ip addresses, used in tcpdump filtration (empty by default, dump for all destination ip).",
    action="append",
)
parser.add_argument(
    "--direction",
    type=str,
    help="Type of collected traffic(in|put)",
    action="append",
)

args = parser.parse_args()

Log = Logger()
Log.run(
    args.ethname,
    exec_time=args.exec_time,
    file_size=args.file_size,
    file_count=args.file_count,
    file_name=args.file_name,
    src_ports=args.src_port,
    dst_ports=args.dst_port,
    src=args.src,
    dst=args.dst,
    direction=args.direction,
)
