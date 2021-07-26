import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import os
from optparse import OptionParser
import multiprocessing
import yaml
import re
import logging
from collections import defaultdict


def success_return(message=None, data=None):
    """

    :param message:
    :param data:
    :return:
    """
    return {'code': 'success', 'message': message, 'data': data}


def false_return(message=None, data=None):
    """

    :param message:
    :param data:
    :return:
    """
    return {'code': 'fail', 'message': message, 'data': data}


def now_ts():
    now = datetime.datetime.now()
    return now.strftime('%Y%m%d-%H%M%S')


def parsArgs():
    hstr = '%prog [options]'
    parser = OptionParser(hstr, version='%prog 0.1')
    parser.add_option("-c", "--config", dest="config", help="The local config path")
    # parser.add_option("-i", "--interface", dest="interface", help="The interface to dump packets")

    (options, args) = parser.parse_args()

    if not options:
        parser.error("incorrect number of arguments")

    if options.config is None:
        parser.error("-c config file is required")

    if not os.path.exists(options.config):
        parser.error("{} not exists".format(options.config))
    else:
        try:
            with open(options.config) as f:
                return yaml.safe_load(f)
        except Exception as e:
            parser.error(str(e))

    return True


def cap(iface, file_dir, params, cpu):
    """
    抓包
    :param iface:
    :param file_dir:
    :param params:
    :param cpu:
    :return:
    """
    ts = now_ts()
    print('do func time :', ts)
    file_path = os.path.join(file_dir, "wirecap_{}_%Y%m%d-%H%M%S.pcap".format(iface, ts))
    logger.debug('start to capture packets of interface {}, write to file {}'.format(iface, file_path))
    os.system('/usr/bin/taskset -c {} /usr/sbin/tcpdump -i {} -w {} {}'.format(cpu, iface, file_path, params))


def kill_proc(interface, file_dir):
    """
    杀死指定进程
    :param interface:
    :return:
    """
    ts = now_ts()
    print('do func2 time：', ts)
    os.system(
        'ps aux | grep tcpdump | grep ' +
        interface + ' | grep ' + file_dir + ' | grep -v grep | awk \'{print $2}\' | xargs kill -9')


def validate_timesync():
    pass


def checksum_compare(source, target, reserve_days):
    """
    
    :param source: 源目录， 本地目录
    :param target: 目标目录，一般为rsync的目标目录
    :param reserve_days: 保留文件天数，如果是30，表示查找源目录中创建日期比现在大30天的
    :return: 
    """
    try:
        source_md5 = list()
        target_md5 = list()
        sync_files = list()
        s_files = os.popen("find {} -type f -ctime +{}".format(source, reserve_days)).read().split('\n')
        t_files = os.popen("find {} -type f".format(target)).read().split('\n')
        for sf in s_files:
            if sf:
                s_md5 = os.popen('md5sum {}'.format(sf)).read().split()[0]
                source_md5.append({'md5': s_md5, 'filename': sf})

        if remote_dir is not None:
            for tf in t_files:
                if tf:
                    t_md5 = os.popen('md5sum {}'.format(tf)).read().split()[0]
                    target_md5.append(t_md5)

            for sm in source_md5:
                if sm['md5'] in target_md5:
                    sync_files.append(sm['filename'])
        else:
            for sm in source_md5:
                sync_files.append(sm['filename'])

        return sync_files
    except Exception as e:
        logger.error(str(e))
        return False


def validate_df(dir_path):
    try:
        df_info = os.popen("df {} | grep -v Mount".format(dir_path)).read().split()
        total = df_info[1]
        used = df_info[2]
        avail = df_info[3]
        capacity = df_info[4]
        mounted = df_info[-1]
        _size = os.popen("du {} | grep '{}$'".format(dir_path, dir_path)).read().split()[0]
        return success_return(data={'self_occupy': eval(_size) / eval(total) * 100,
                                    'total_used': eval(capacity.strip('%')),
                                    'available': avail})
    except Exception as e:
        logger.error(str(e))
        return false_return(message=str(e))


def rotate(dir_path, reserve_days, percent, remote_path=None):
    disk_info = validate_df(dir_path)
    if disk_info['total_used'] >= percent:
        check_result = checksum_compare(dir_path, remote_path, reserve_days)
        if check_result:
            logger.info('Deleting {}'.format(check_result))
            for f in check_result:
                os.remove(f)


class ScheduleCap:
    def __init__(self):
        self.scheduler = BlockingScheduler()

    def add(self, **kwargs):
        """

        :param kwargs:         func=cap,
                               trigger='cron',
                               second=00,
                               minute=45,
                               hour=16,
                               day_of_week='mon-fri'
                               args=[iface, file_dir, params]
        :return:
        """
        self.scheduler.add_job(**kwargs)

    def start_cap(self):
        self.scheduler.start()


def merge_files(dir_path, ifs):
    merge_list = dict()
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            _, i, _t = file.split('_')
            t = _t.split('.')[0]
            if t not in merge_list.keys():
                merge_list[t] = list()
            # 若网卡在合并列表内，则合并
            if i in ifs:
                merge_list[t].append(file)
    for time, f in merge_list:
        if len(f) > 1:
            files_str = ' '.join(f)

            target_file = os.path.join(dir_path, 'merged', 'wirecap_{}.pcap'.format(time))
            os.system('mergecap -a {} -w {}'.format(files_str, target_file))

    return None


if __name__ == "__main__":
    # 读入参数
    cfg = parsArgs()

    # 初始化schedule
    sc = ScheduleCap()

    # global config
    store_path = cfg.get('store_path', "/data/tcpdump")
    reserve = cfg.get('reserve', 60)
    cpu = cfg.get('cpu', 0)
    mergecap = cfg.get('mergecap', 1)
    log_path = cfg.get('log_path', "/var/log/tcpdump")
    remote_dir = cfg.get('remote_dir', "/data/sync/")
    rotate_percent = cfg.get('rotate_percent', 90)

    merged_path = os.path.join(store_path, 'merged')

    # 检查目标文件夹，不存在则创建
    for path in (store_path, merged_path, log_path):
        if not os.path.exists(path):
            os.makedirs(path)

    # log 输出
    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')
    logger = logging.getLogger()
    hdlr = logging.FileHandler(os.path.join(log_path, "algocap.log"))
    formatter = logging.Formatter(fmt='%(asctime)s - %(module)s-%(funcName)s - %(levelname)s - %(message)s',
                                  datefmt='%m/%d/%Y %H:%M:%S')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)

    # 记录需要监控的网卡端口
    monitor_interface = list()

    # add tcpdump jobs
    for job in cfg.get('tcpdump'):
        interface = job.get('interface')
        monitor_interface.append(interface)
        params = job.get('params')
        schedules = job.get('schedules')
        for s in schedules:
            trigger = s.get('trigger')
            s_minute, s_hour, s_day, s_month, s_week = s.get('start').split()
            e_minute, e_hour, e_day, e_month, e_week = s.get('end').split()
            start_kwargs = {
                'func': cap,
                'trigger': trigger,
                'minute': int(s_minute) if not re.search(r"\*", s_minute) else None,
                'hour': int(s_hour) if not re.search(r"\*", s_hour) else None,
                'day': int(s_day) if not re.search(r"\*", s_day) else None,
                'month': int(s_month) if not re.search(r"\*", s_month) else None,
                'day_of_week': s_week if s_week else None,
                'args': [interface, store_path, params, cpu]
            }

            end_kwargs = {
                'func': kill_proc,
                'trigger': trigger,
                'minute': int(e_minute) if not re.search(r"\*", e_minute) else None,
                'hour': int(e_hour) if not re.search(r"\*", e_hour) else None,
                'day': int(e_day) if not re.search(r"\*", e_day) else None,
                'month': int(e_month) if not re.search(r"\*", e_month) else None,
                'day_of_week': e_week if e_week else None,
                'args': [interface, store_path]
            }
            sc.add(**start_kwargs)
            sc.add(**end_kwargs)

    # 监控任务
    for monitor in cfg.get('monitor'):
        _kwargs = dict()
        trigger = monitor.get('trigger')
        minute, hour, day, month, week = monitor.get('start').strip().split()
        _kwargs = {
            'trigger': trigger,
            'minute': int(minute) if not re.search(r"\*", minute) else None,
            'hour': int(hour) if not re.search(r"\*", hour) else None,
        }

        if monitor.get('item') == "time":
            pass

        if monitor.get('item') == "rotate":
            _kwargs['func'] = rotate
            _kwargs['args'] = [store_path, reserve, rotate_percent, remote_dir]

        if monitor.get('item') == "merge":
            _kwargs['func'] = merge_files
            _kwargs['args'] = [store_path, monitor_interface]

        if _kwargs:
            sc.add(**_kwargs)

    print(sc.scheduler.get_jobs())

    sc.start_cap()
