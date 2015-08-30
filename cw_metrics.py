#!/usr/bin/env python
"""
Collect usage for different monitors and send the data to AWS CloudWatch

Version: 1.1
Author: David Golovan

--------

Copyright 2015 Forthscale

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from __future__ import division
import re
import os
import time
import logging
import ConfigParser
import inspect
from sys import exit
from collections import deque
from boto.ec2 import cloudwatch, connect_to_region
from boto.utils import get_instance_metadata
from collections import namedtuple


class MonitorConfig(object):
    def __init__(self, metric=5, sendmetrics=5):
        self.metrics = int(metric)
        self.sendMetricsCount = int(sendmetrics)
        self.periodsCount = 0
        self.monitorData = deque(maxlen=self.metrics)

    def set_metrics(self, metric):
        self.metrics = int(metric)
        self.monitorData = deque(maxlen=self.metrics)

    def set_metrics_count(self, sendmetrics):
        self.sendMetricsCount = int(sendmetrics)

    def add_usage(self, usage):
        self.monitorData.appendleft(usage)
        self.periodsCount += 1

    def null_period(self):
        self.periodsCount = 0

    def update_metrics(self, metric, sendmetrics):
        if self.metrics != int(metric):
            self.set_metrics(metric)
        if self.sendMetricsCount != int(sendmetrics):
            self.set_metrics_count(sendmetrics)


def init_logger(haveconfigfile):
    """
    Configure logger to use new format and files if specified in config.
    All params taken from config file
    :return: True if success
    """
    try:
        logformat = '%(asctime)s - %(levelname)s - %(message)s'
        loglevel = getattr(logging, 'WARNING'.upper())
        if haveconfigfile:
            if Config.has_option('Global', 'LogLevel'):
                loglevel = getattr(logging, Config.get('Global', 'LogLevel').upper())
            if Config.has_option('Global', 'Logfile'):
                logfile = '{0}/{1}'.format(scriptBase, Config.get('Global', 'LogFile'))
                logging.basicConfig(filename=logfile, format=logformat, level=loglevel,
                                    when='midnight', interval=1, backupCount=5)
        logging.basicConfig(format=logformat, level=loglevel,
                            when='midnight', interval=1, backupCount=5)
        return True
    except Exception:
        print '"I haven\'t cried like that since "Titanic.""\nFailed to init logger'
        exit(3)


def init_pid():
    """
    Check if another process is already running, if not create new pid file
    """
    pid_file_name = '{0}.pid'.format(scriptName)
    pid_file_path = '{0}/{1}'.format(scriptBase, pid_file_name)
    pid = str(os.getpid())
    if os.path.isfile(pid_file_path):
        logging.warning('{0} already exists, check if the program is running'.format(pid_file_name))
        pid_file = open(pid_file_path, "r")
        pid_file.seek(0)
        old_pid = pid_file.readline()
        if os.path.exists("/proc/{0}".format(old_pid)):
            logging.info('Script is still running...')
            exit(1)
        else:
            logging.error('The script is not running, but we have pid file - {0}'.format(pid_file_path))
            logging.debug('Time to call Tallahassee!')
            try:
                os.remove(pid_file_path)
            except Exception:
                logging.error('Can\'t delete old pid file - {0}'.format(pid_file_path))
                logging.debug('"This is now the United States of Zombieland."')
                exit(2)
            else:
                logging.info('Old pid file was removed')
                logging.debug('"My mama always told me someday I\'d be good at something. Who\'d a guessed that '
                              'something\'d be zombie killing?"')

    else:
        file(pid_file_path, 'w').write(pid)
        logging.debug('{0} pid saved to pid file {1}'.format(pid, pid_file_name))
        logging.debug('"Oh, this Twinkie thing, it ain\'t over yet.')


def init_file_config():
    if Config.has_section('MemUsage'):
        monitorConfig['MemUsage'] = MonitorConfig()
        if Config.has_option('MemUsage', 'Metrics'):
            monitorConfig['MemUsage'].set_metrics(Config.get('MemUsage', 'Metrics'))
        if Config.has_option('MemUsage', 'SendMetricsCount'):
            monitorConfig['MemUsage'].set_metrics_count(Config.get('MemUsage', 'SendMetricsCount'))
    if Config.has_section('InodesUsage'):
        monitorConfig['InodesUsage'] = MonitorConfig()
        if Config.has_option('InodesUsage', 'Metrics'):
            monitorConfig['InodesUsage'].set_metrics(Config.get('InodesUsage', 'Metrics'))
        if Config.has_option('InodesUsage', 'SendMetricsCount'):
            monitorConfig['InodesUsage'].set_metrics_count(Config.get('InodesUsage', 'SendMetricsCount'))
    if Config.has_section('DiskUsage'):
        monitorConfig['DiskUsage'] = MonitorConfig()
        if Config.has_option('DiskUsage', 'Metrics'):
            monitorConfig['DiskUsage'].set_metrics(Config.get('DiskUsage', 'Metrics'))
        if Config.has_option('DiskUsage', 'SendMetricsCount'):
            monitorConfig['DiskUsage'].set_metrics_count(Config.get('DiskUsage', 'SendMetricsCount'))
    if Config.has_section('SwapUsage'):
        monitorConfig['SwapUsage'] = MonitorConfig()
        if Config.has_option('SwapUsage', 'Metrics'):
            monitorConfig['SwapUsage'].set_metrics(Config.get('SwapUsage', 'Metrics'))
        if Config.has_option('SwapUsage', 'SendMetricsCount'):
            monitorConfig['SwapUsage'].set_metrics_count(Config.get('SwapUsage', 'SendMetricsCount'))


def init_tag_config():
    """
    Look for tag in EC2 with monitoring configuration. If it's there enable this monitoring
    :return: True if there is at least one monitor configured
    """
    # Connect to EC2 and get the tag
    try:
        conn = connect_to_region(region)
        tag = conn.get_all_tags(filters={'resource-id': instance_id, 'key': monitoring_tag})
    except Exception:
        logging.error('Can\'t get tags from EC2')
        logging.debug('"In Mexico, you know what they call Twinkies? \'Los submarinos.\'"')
        return False
    else:
        config_flag = False
        # Verify that we have the tag
        if tag:
            # Split the tag to get the data
            tag_data = dict(item.split('=') for item in tag[0].value.split(';'))
            if 'MemUsage' in tag_data:
                # If it's first time we see this tag, init the class, otherwise check if need to update
                if 'MemUsage' not in monitorConfig:
                    monitorConfig['MemUsage'] = MonitorConfig(tag_data['MemUsage'], tag_data['MemUsage'])
                else:
                    monitorConfig['MemUsage'].update_metrics(tag_data['MemUsage'], tag_data['MemUsage'])
                config_flag = True
            else:
                logging.debug('Failed to verify "MemUsage" from tag')
                logging.debug('"I\'ve never hit a kid before. I mean, that\'s like asking who Gandhi is."')
            if 'InodesUsage' in tag_data:
                # If it's first time we see this tag, init the class, otherwise check if need to update
                if 'MemUsage' not in monitorConfig:
                    monitorConfig['InodesUsage'] = MonitorConfig(tag_data['InodesUsage'], tag_data['InodesUsage'])
                else:
                    monitorConfig['InodesUsage'].update_metrics(tag_data['InodesUsage'], tag_data['InodesUsage'])
                config_flag = True
            else:
                logging.debug('Failed to verify "InodesUsage" from tag')
                logging.debug('"I\'ve never hit a kid before. I mean, that\'s like asking who Gandhi is."')
            if 'DiskUsage' in tag_data:
                # If it's first time we see this tag, init the class, otherwise check if need to update
                if 'DiskUsage' not in monitorConfig:
                    monitorConfig['DiskUsage'] = MonitorConfig(tag_data['DiskUsage'], tag_data['DiskUsage'])
                else:
                    monitorConfig['DiskUsage'].update_metrics(tag_data['DiskUsage'], tag_data['DiskUsage'])
                config_flag = True
            else:
                logging.debug('Failed to verify "DiskUsage" from tag')
                logging.debug('"I\'ve never hit a kid before. I mean, that\'s like asking who Gandhi is."')
            if 'SwapUsage' in tag_data:
                # If it's first time we see this tag, init the class, otherwise check if need to update
                if 'SwapUsage' not in monitorConfig:
                    monitorConfig['SwapUsage'] = MonitorConfig(tag_data['SwapUsage'], tag_data['SwapUsage'])
                else:
                    monitorConfig['SwapUsage'].update_metrics(tag_data['SwapUsage'], tag_data['SwapUsage'])
                config_flag = True
            else:
                logging.debug('Failed to verify "SwapUsage" from tag')
                logging.debug('"I\'ve never hit a kid before. I mean, that\'s like asking who Gandhi is."')
            # Return True if found something or False
            return config_flag
        else:
            logging.warning('No monitoring tag found')
            logging.debug('"You got taken hostage by a 12 year old?"')
            return False


def collect_memory_usage():
    """
    Collect server memory usage from /proc/meminfo
    :return: Dictionary of mem usage on server
    """
    meminfo = {}
    pattern = re.compile('([\w\(\)]+):\s*(\d+)(:?\s*(\w+))?')
    with open('/proc/meminfo') as f:
        for line in f:
            match = pattern.match(line)
            if match:
                # For now we don't care about units (match.group(3))
                meminfo[match.group(1)] = float(match.group(2))
    return meminfo


def disk_usage(path):
    """
    Return disk usage associated with path.
    :param path: Mount path to check
    :return: Disk usage
    """
    usage_ntuple = namedtuple('usage',  'total used free percent')
    st = os.statvfs(path)
    free = (st.f_bavail * st.f_frsize)
    total = (st.f_blocks * st.f_frsize)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    try:
        percent = (float(used) / total) * 100
    except ZeroDivisionError:
        percent = 0
    # NB: the percentage is -5% than what shown by df due to
    # reserved blocks that we are currently not considering:
    # http://goo.gl/sWGbH
    return usage_ntuple(total, used, free, round(percent, 1))


def send_multi_metrics(instanceid, aws_region, cw_metrics, namespace='EC2/Infrastructure', unit='Percent'):
    """
    Send multiple metrics to CloudWatch
    metrics is expected to be a map of key -> value pairs of metrics
    :param instanceid: AWS instance ID
    :param aws_region: AWS region
    :param cw_metrics:
    :param namespace: Namespace to store the CloudWatch metric
    :param unit: What unit to store the CloudWatch metric
    """
    cw = cloudwatch.connect_to_region(aws_region)
    cw.put_metric_data(
        namespace,
        cw_metrics.keys(),
        unit=unit,
        dimensions={"InstanceId": instanceid},
        statistics=cw_metrics.values()
    )


def aggregate_metrics(metric_list):
    """
    Make aggregation for list of metrics
    :param metric_list: List of latest metrics
    :return: Aggregated list of metrics for CloudWatch
    """
    agr_metrics = {
        'maximum': max(metric_list),
        'minimum': min(metric_list),
        'samplecount': len(metric_list),
        'sum': round(float(sum(metric_list)), 2),
        'average': round(float(sum(metric_list)/len(metric_list)), 2)
    }
    return agr_metrics

 
if __name__ == '__main__':
    # Find script name and path
    scriptName = os.path.basename(os.path.abspath(inspect.getsourcefile(lambda: 0)))[:-3]
    scriptBase = os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0)))
    # Get config
    have_config_file = True
    have_config_tag = True
    send_metrics = {}
    monitorConfig = {}
    # Set sleep time between checks
    sleep_period = 60
    monitoring_tag = 'CW_Monitoring'
    if os.path.isfile('{0}/{1}.ini'.format(scriptBase, scriptName)):
        Config = ConfigParser.ConfigParser()
        Config.read('{0}/{1}.ini'.format(scriptBase, scriptName))
        # Init logger
        init_logger(have_config_file)
        # Set sleep time between checks
        if Config.has_option('Global', 'Period'):
            sleep_period = int(Config.get('Global', 'Period'))
        # Set custom moniroring tag
        if Config.has_option('Global', 'Tag'):
            monitoring_tag = int(Config.get('Global', 'Tag'))
        init_file_config()
    else:
        have_config_file = False
        # Init logger
        init_logger(have_config_file)
        # We don't exit if there is no config, because there might be tags for config
        logging.warning('No config file found\n{0}/{1}.ini'.format(scriptBase, scriptName))
        logging.debug('"Where are you, you spongy, yellow, delicious bastards?"')
    logging.info('Starting the monitoring process')
    logging.debug('"There\'s a box of Twinkies in that grocery store."')
    # Init pid
    init_pid()
    # This is for AWS servers
    # For each known monitor we create array that work as FIFO and can hold number of metrics for each period
    try:
        metadata = get_instance_metadata(timeout=2, num_retries=2)
        instance_id = metadata['instance-id']
        region = metadata['placement']['availability-zone'][0:-1]
    except Exception:
        logging.error('Can\'t connect to EC2 and get metadata')
        logging.debug('"Don\'t kill me with my own gun."')
    else:
        logging.info('Monitor is working on instance {0} in AWS region {1}'.format(instance_id, region))
        logging.debug('"That place totally blows!"')

    # Now run the monitors in endless loop.
    # Each monitor will be checked if it's configured in config file
    while instance_id and region:
        # Get monitor tag if exists to config
        have_config_tag = init_tag_config()

        # Check that we have one of the configs
        if not have_config_file and not have_config_tag:
            logging.error('No configuration! Can\'t run!')
            logging.debug('"You\'re not a zombie, you\'re talking and... You\'re okay? "')

        # RAM Memory Monitor
        if 'MemUsage' in monitorConfig:
            mem_usage = collect_memory_usage()
            # Convert collect data to how much free and used memory we have(including buffers and cache)
            mem_free = mem_usage['MemFree'] + mem_usage['Buffers'] + mem_usage['Cached']
            mem_used = mem_usage['MemTotal'] - mem_free
            # Convert to percents and add to monitor data array
            mem_percents = round((mem_used / mem_usage['MemTotal'] * 100), 2)
            monitorConfig['MemUsage'].add_usage(mem_percents)
            logging.debug('Memory usage {0}%'.format(mem_percents))
            # Create the aggregation for the metrics
            aggregated_metrics = aggregate_metrics(monitorConfig['MemUsage'].monitorData)
            logging.debug('Aggregated Memory {0}'.format(aggregated_metrics))
            logging.debug('Memory Period counter {0}'.format(monitorConfig['MemUsage'].periodsCount))
            # If we reached the counter send metric and set the counter back to zero
            if monitorConfig['MemUsage'].periodsCount == monitorConfig['MemUsage'].sendMetricsCount:
                logging.debug('Reached Memory Period counter limit {0}'
                              .format(monitorConfig['MemUsage'].periodsCount))
                monitorConfig['MemUsage'].null_period()
                send_metrics['MemUsage'] = aggregated_metrics

        # Swap Memory Monitor
        if 'SwapUsage' in monitorConfig:
            # We collect the memory data again, incase RAM monitor is turrend off
            if not mem_usage:
                mem_usage = collect_memory_usage()
            # If swap enebaled do the math, if not set it to 0
            if mem_usage['SwapTotal'] != 0:
                swap_used = mem_usage['SwapTotal'] - mem_usage['SwapFree'] - mem_usage['SwapCached']
                swap_percent = round(swap_used / mem_usage['SwapTotal'] * 100, 2)
            else:
                swap_percent = 0
            # Add to monitor data array
            monitorConfig['SwapUsage'].add_usage(swap_percent)
            logging.debug('Swap usage {0}%'.format(swap_percent))
            # Create the aggregation for the metrics
            aggregated_metrics = aggregate_metrics(monitorConfig['SwapUsage'].monitorData)
            logging.debug('Aggregated Swap {0}'.format(aggregated_metrics))
            logging.debug('Swap Period counter {0}'.format(monitorConfig['SwapUsage'].periodsCount))
            # If we reached the counter send metric and set the counter back to zero
            if monitorConfig['SwapUsage'].periodsCount == monitorConfig['SwapUsage'].sendMetricsCount:
                logging.debug('Reached Swap Memory Period counter limit {0}'.
                              format(monitorConfig['SwapUsage'].periodsCount))
                monitorConfig['SwapUsage'].null_period()
                send_metrics['SwapUsage'] = aggregated_metrics

        # iNodes monitor
        if 'InodesUsage' in monitorConfig:
            # Collect inode data for root disk
            # TODO add monitor for more FS's
            inodes_free = os.statvfs('/').f_favail
            inodes_total = os.statvfs('/').f_files
            # Convert to percents and add to monitor data array
            inode_percent = round(((inodes_total - inodes_free) / inodes_total * 100), 2)
            monitorConfig['InodesUsage'].add_usage(inode_percent)
            logging.debug('Inode usage {0}%'.format(inode_percent))
            # Create the aggregation for the metrics
            aggregated_metrics = aggregate_metrics(monitorConfig['InodesUsage'].monitorData)
            logging.debug('Aggregated Inode {0}'.format(aggregated_metrics))
            logging.debug('Inode Period counter {0}'.format(monitorConfig['InodesUsage'].periodsCount))
            # If we reached the counter send metric and set the counter back to zero
            if monitorConfig['InodesUsage'].periodsCount == monitorConfig['InodesUsage'].sendMetricsCount:
                logging.debug('Reached INodes Period counter limit {0}'.
                              format(monitorConfig['InodesUsage'].periodsCount))
                monitorConfig['InodesUsage'].null_period()
                send_metrics['InodesUsage'] = aggregated_metrics

        # Disk space monitor
        if 'DiskUsage' in monitorConfig:
            # Working on root mount
            # TODO add more mounts
            paths = '/'
            # Get the data and add to monitor data array as percents
            disk_percent = round(disk_usage(paths).percent, 2)
            monitorConfig['DiskUsage'].add_usage(disk_percent)
            logging.debug('Disk usage {0}%'.format(disk_percent))
            # Create the aggregation for the metrics
            aggregated_metrics = aggregate_metrics(monitorConfig['DiskUsage'].monitorData)
            logging.debug('Aggregated Disk {0}'.format(aggregated_metrics))
            logging.debug('Disk Period counter {0}'.format(monitorConfig['DiskUsage'].periodsCount))
            # If we reached the counter send metric and set the counter back to zero
            if monitorConfig['DiskUsage'].periodsCount == monitorConfig['DiskUsage'].sendMetricsCount:
                logging.debug('Reached Disk Period counter limit {0}'.
                              format(monitorConfig['DiskUsage'].periodsCount))
                monitorConfig['DiskUsage'].null_period()
                send_metrics['DiskUsage'] = aggregated_metrics

        # Send CloudWatch metrics only if we have something to send
        if send_metrics:
            logging.info('Sending metrics')
            logging.debug('"Hop in the car, Evel Knievel. Let\'s go ride the rollercoaster."')
            logging.debug('Metrics to send {0}'.format(send_metrics))
            send_multi_metrics(instance_id, region, send_metrics)
            # Metrics were sent, null them
            send_metrics = {}
            logging.debug('Setting metrics to null {0}'.format(send_metrics))
        # Sleep before next check
        logging.debug('Going to sleep for {0} seconds'.format(sleep_period))
        logging.debug('"Time to nut up or shut up!"')
        time.sleep(sleep_period)
