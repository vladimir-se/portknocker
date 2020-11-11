#!/usr/bin/env python3
#coding: utf-8


import time
import datetime
import os
import sys
import logging
import argparse
import re
from threading import Thread


# Management netfilter rules.
from netfilter.rule import Rule,Match
from netfilter.table import Table
# System and process utilities.
import psutil
# Process demonisation.
from daemons.prefab import run


class PortKnocker(run.RunDaemon):
    '''
    Class for analysis iptables log messages and open port upon attempt connect to port.
    '''
    def __init__(self, pidfile):
        super().__init__(pidfile=pidfile)

        # Files for processing.
        self.iptables_logfile = "/var/log/syslog"
        self.dumpfile = os.path.dirname(os.path.realpath(__file__)) + os.sep + "portknocker.dmp"

        # Logger parameters for daemon. 
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.fh = logging.FileHandler('/var/log/portknocker_daemon.log')
        self.fh.setLevel(logging.INFO)
        self.formatstr = '%(asctime)s - %(levelname)s - %(message)s'
        self.formatter = logging.Formatter(self.formatstr)
        self.fh.setFormatter(self.formatter)
        self.logger.addHandler(self.fh)

        # Netfilter table for setting rules.
        self.table = Table("filter")
        
        # Reserved ports {"in_int:port":"src_ip"}.
        self.ports = dict()
        
        # Clean for start, stop and restart daemon.
        self.clean()


    def tail(self, monfile):
        '''
        Get last line in file,  similarly to tail -f filename.
        '''
        try:
            monfile.seek(0, os.SEEK_END)
        except:
            self.logger.error("Error while log-file parsing.")

        while True:
            try:
                line = monfile.readline()
            except:
                self.logger.error("Error while read log-file.")
            if not line:
                time.sleep(0.1)
                continue
            yield line


    def set_rule(self, in_int, port, src_ip):
        '''
        Make netfilter rule.
        -I INPUT -i $int_in -p tcp --dport $port -j ACCEPT
        '''        
        rule = Rule(
            in_interface = f"{in_int}",
            source = f"{src_ip}",
            protocol = "tcp",
            matches = [Match("tcp", f"--dport {port}")],
            jump = "ACCEPT")
        return rule


    def check_netfilter_rule(self, in_int, port, src_ip):
        '''
        Check rule availability in netfilter.
        '''
        return True if self.set_rule(in_int, port, src_ip) in [_rule for _rule in self.table.list_rules("INPUT")] else False


    def set_netfilter_rule(self, in_int, port, src_ip):
        '''
        Set netfilter rule.
        '''
        try:
            if not self.check_netfilter_rule(in_int, port, src_ip):
                self.table.prepend_rule("INPUT", self.set_rule(in_int, port, src_ip))
                self.logger.info(f"Add netfilter rule for in_int:{in_int} port:{port} src_ip:{src_ip}")
        except:
            self.logger.error(f"Rule setting error, in_int:{in_int} port:{port} src_ip:{src_ip}")


    def delete_netfilter_rule(self, in_int, port, src_ip):
        '''
        Delete netfilter rule.
        -D INPUT -t in_int -s src_ip --dport $port
        '''
        try:
            if self.check_netfilter_rule(in_int, port, src_ip):
                self.table.delete_rule('INPUT', self.set_rule(in_int, port, src_ip))
                self.logger.info(f"Delete netfilter rule for in_int:{in_int} port:{port} src_ip:{src_ip}")
        except:
                self.logger.error(f"Error removing netfilter rule, in_int:{in_int} port:{port} src_ip:{src_ip}")


    def checking_established_connections(self, in_int, port, src_ip):
        '''
        Check established port connection.
        If not established connection, then delete for opening port netfilter rule.
        '''
        while True:
            # Timeoute for establish connection.
            time.sleep(30)
            # Enumeration of available connections by port number and connection status.
            if [port, "ESTABLISHED"] in [[str(conn.laddr.port), conn.status] for conn in psutil.net_connections()]:
                self.logger.info(f"Connection ESTABLISHED port:{port} src_ip:{src_ip}")
                # Timeout before next check connection status.
                time.sleep(30)
            else:
                try:
                    # Delete iptables rule for port opening..
                    self.delete_netfilter_rule(in_int, port, src_ip)
                    self.logger.info(f"Disconnect in_int: port:{port} src_ip:{src_ip}")
                    # Delete port from list reservated.
                    self.deleting_reserved_port(f"{in_int}:{port}")
                    return True
                except:
                    self.logger.error(f"Error while closing the connection, port:{port} src_ip:{src_ip}")
                    return False


    def save_reservated_ports_set_to_disk(self):
        '''
        Save list reserved ports to file.
        '''
        try:
            with open(self.dumpfile, "w") as dumpfile:
                if len(self.ports):
                    for in_int_port, src_ip in self.ports.items():
                        dumpfile.write(f"{in_int_port}:{src_ip}\n")
            os.chmod(self.dumpfile, 0o600)
        except:
            self.logger.error("Error writing dump file.")


    def get_reservated_ports_from_dumpfile(self):
        '''
        Get list reserved ports from file.
        '''
        try:
            if os.path.exists(self.dumpfile) and (os.path.getsize(self.dumpfile) > 1):
                with open(self.dumpfile, "r") as dumpfile:
                    self.ports = { f"{in_int}:{port}":src_ip for in_int, port, src_ip in [port.rstrip().split(':') for port in dumpfile.readlines()]}
        except:
            self.logger.error("Error while get reserved ports from file.")


    def set_reservated_port(self, in_int, port, src_ip):
        '''
        Save port number to list reserved ports and save this list to file.
        '''
        try:
            self.ports[f"{in_int}:{port}"] = src_ip
            self.save_reservated_ports_set_to_disk()
        except:
            self.logger.error("Error saving the reserved port.")


    def deleting_all_created_rules(self):
        '''
        Delete all set rule.
        If in memory not reserved ports, then checking records in dumpfile.
        '''
        try:
            # Actions "start" and "stop" create new class copy, 
            # him need loading list reserved ports.в
            if not len(self.ports):
                self.get_reservated_ports_from_dumpfile()
            for in_int_port, src_ip in self.ports.items():
                in_int,port = in_int_port.split(':')
                self.delete_netfilter_rule(in_int, port, src_ip)
        except:
            self.logger.warning("Error while remove all rule with reserved ports.")
            return False
        return True


    def clean_reservated_port_file(self):
        '''
        Delete dumpfile.
        '''
        try:
            os.remove(self.dumpfile)
        except:
            self.logger.warning("Error while remove dumpfile. Dumpfile may be missing.")


    def deleting_reserved_port(self, in_int_port):
        '''
        Delete port from list reserved ports and
        save actual list to disk.
        '''
        try:
            if len(self.ports):
                self.ports.pop(in_int_port, 0)
                self.save_reservated_ports_set_to_disk()
        except:
            self.logger.error("Error deleting reserved port.")


    def port_connection_reservate(self):
        '''
        Reserve port and set netfilter rule for port opening.
        '''
        # Counter attempting connection to port.
        port_knock_counter = {}
        # Dictionary of active timer threads.
        timer_threads = {}
        # Dictionary of threads active observed connections.
        connection_threads = {}
        def reservate(in_int, port, src_ip):
            # Port connection attempt counting.
            port_knock_counter[port] = port_knock_counter.setdefault(port, 0)
            port_knock_counter[port] += 1
            # If attempt not one, then running timer.
            if port_knock_counter[port] == 2:
                timer_thread = Thread(name = port, target = time.sleep, args = (10,), daemon = True)
                timer_threads[port] = timer_thread
                timer_thread.start()
            # Reservate port after five attempting and reset attempt counter.
            if port_knock_counter[port] == 5:
                self.set_reservated_port(in_int, port, src_ip)
                port_knock_counter[port] = 0
                # Because checking thread activity can call exception,  do this.
                connection_threads[port] = Thread(name = port)
                if not timer_threads[port].is_alive() and not connection_threads[port].is_alive():
                    # Reset attempt counter after stopping timer.
                    port_knock_counter[port] = 0
                # Create netfilter rule for reserved port and starting observed.
                if [key for key in self.ports.keys() if [in_int, port] in [key.split(':')]]:
                    # Sets netfilter rules.
                    self.set_netfilter_rule(in_int, port, src_ip)
                    try:
                        # The flow, in which carried out observant to connection and deleting netfilter rule after disconnect to port.
                        connection_thread = Thread(name = port, target = self.checking_established_connections, args = (in_int, port, src_ip,), daemon = True)
                        connection_threads[port] = connection_thread
                        connection_thread.start()
                    except:
                        self.logger.error('Error creating connection control thread!')
        return reservate


    def clean(self):
        '''
        Netfilter rules and dumpfile clean when daemon restarted or stopping.
        '''
        try:
            self.deleting_all_created_rules()
            self.clean_reservated_port_file()
            self.logger.info('PortKnocker stopped ...')
        except:
            self.logger.error('Error clearing rules.')


    def run(self):
        '''
        Master cycle running netfilter log file analyser for search in him new connection records. 
        You need set netfilter rule, equivalent to this template:
        -A INPUT -i eno1 -p tcp -m multiport --dports $start_port:$end_port -j LOG --log-prefix "Iptables: port_knocker "
        '''
        self.logger.info("PortKnocker running ...")
        reserved_port = self.port_connection_reservate()
        with open(self.iptables_logfile, "w+") as f:
            for line in self.tail(f):
                # Long enough record in netfilter log file containing: string "Iptables: port_knocker", 
                # input interface, destination port and note about SYN type package.
                if ("Iptables: port_knocker" in line) and (line.find(" DPT=") and line.find(" SYN ")):
                    reserved_port(str(*re.findall(r"IN=\w+", line))[3:], str(*re.findall(r"DPT=\d+", line))[4:], str(*re.findall(r"SRC=[\d+\.]+", line))[4:])


if __name__ == "__main__":

    portknocker = PortKnocker('/var/run/portknocker.pid')


    def start(arg):
        portknocker.start()

    def stop(arg):
        portknocker.stop()

    def restart(arg):
        portknocker.restart()


    parser = argparse.ArgumentParser(description = "PortKnocker daemon.")
    subparser = parser.add_subparsers(help = "Daemon parameters.")    

    start_daemon = subparser.add_parser("start", help="Run PortKnocker daemon.")
    start_daemon.set_defaults(func = start)

    stop_daemon = subparser.add_parser("stop", help="Stop PortKnocker daemon.")
    stop_daemon.set_defaults(func = stop)
    
    restart_daemon = subparser.add_parser("restart", help="Restart PortKnocker daemon.")
    restart_daemon.set_defaults(func = restart)

    args = parser.parse_args()
    parser.print_usage() if not vars(args) else args.func(args)