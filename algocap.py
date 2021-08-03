import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import os
from optparse import OptionParser
import yaml
import re
import logging
import traceback
import time


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

    if not os.path.exists('/usr/sbin/tcpdump'):
        parser.error("/usr/sbin/tcpdump not exists")

    if not os.path.exists('/usr/sbin/lsof'):
        parser.error('/usr/sbin/lsof not exists')

    if not os.path.exists('/usr/sbin/mergecap'):
        parser.error('/usr/sbin/mergecap not exists')

    if not os.path.exists(options.config):
        parser.error("{} not exists".format(options.config))
    else:
        try:
            with open(options.config) as f:
                return yaml.safe_load(f)
        except Exception as e:
            parser.error(str(e))

    return True


def cap(iface, file_dir, params, cpu, date_format):
    """
    抓包
    :param iface:
    :param file_dir:
    :param params:
    :param cpu:
    :param date_format:
    :return:
    """
    ts = now_ts()
    print('do func time :', ts)
    file_path = os.path.join(file_dir, "wirecap_{}_{}.pcap".format(iface, date_format))
    logger.debug('start to capture packets of interface {}, write to file {}'.format(iface, file_path))
    os.system('/usr/bin/taskset -c {} /usr/sbin/tcpdump -i {} -w {} {}'.format(cpu, iface, file_path, params))


def kill_proc(interface, file_dir):
    """
    杀死指定进程
    :param interface:
    :return:
    """
    logger.info("kill tcpdump process " + interface)
    os.system(
        'ps aux | grep tcpdump | grep ' +
        interface + ' | grep ' + file_dir + ' | grep -v grep | awk \'{print $2}\' | xargs kill -s TERM')

    time.sleep(10)
    if os.popen('ps aux | grep tcpdump | grep ' + interface + ' | grep ' + file_dir + ' | grep -v grep'):
        os.system(
            'ps aux | grep tcpdump | grep ' +
            interface + ' | grep ' + file_dir + ' | grep -v grep | awk \'{print $2}\' | xargs kill -9')
    else:
        logger.info(interface + " tcpdump process killed")


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
        delete_list = list()
        # 递归查找源目录下所有文件
        s_files = os.popen("find {} -type f -ctime +{}".format(source, reserve_days)).read().split('\n')
        logger.debug(s_files)
        for sf in s_files:
            if sf:
                sync_file = re.findall("{}(.*)".format(sf), sf)[0]
                command = "rsync -rntv {} {} | grep -v ^$ | wc -l".format(sf, target + sync_file)
                check_ = os.popen(command).read()
                if eval(check_) <= 3:
                    delete_list.append(sf)
        return delete_list
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        return False


def validate_df(dir_path):
    try:
        df_info = os.popen("df {} | grep -v Mount".format(dir_path)).read().split()
        total = df_info[1]
        avail = df_info[3]
        capacity = df_info[4]
        _size = os.popen("du {} | grep '{}$'".format(dir_path, dir_path)).read().split()[0]
        return {'self_occupy': eval(_size) / eval(total) * 100,
                'total_used': eval(capacity.strip('%')),
                'available': avail}
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        return {}


def rotate(dir_path, reserve_days, percent, remote_path=None):
    disk_info = validate_df(dir_path)
    logger.info(disk_info)
    if disk_info and disk_info['total_used'] >= percent:
        logger.info('preparing to confirm file sync sucess...')
        check_result = checksum_compare(dir_path, remote_path, reserve_days)
        if check_result:
            for f in check_result:
                logger.debug("Deleting {}".format(f))
                pass
                # os.remove(f)


def packets_validation(source_list, target_file):
    try:
        sum_source_packets = 0
        for sf in source_list:
            sum_source_packets += eval(
                os.popen('/usr/sbin/capinfos -c -M {} | grep Number'.format(sf)).read().split()[-1])

        target_packets = eval(
            os.popen('/usr/sbin/capinfos -c -M {} | grep Number'.format(target_file)).read().split()[-1])

        if sum_source_packets == target_packets:
            return True
        else:
            return False
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        return False


def merge_files(dir_path, ifs, date_format, precision='hour'):
    merge_list = dict()
    for root, dirs, files in os.walk(dir_path):
        if re.search(r"{}$".format(dir_path), root):
            for file in files:
                if os.path.splitext(file)[-1] != '.pcap':
                    continue
                # 此处t的取值格式需要调整，因为目前是精确到秒，不通网卡启动dump时间可能存在差异，因为要格式化为datetime取小时来判断
                _, i, _t = file.split('_')
                t = _t.split('.')[0]
                file_date = datetime.datetime.strptime(t, date_format)
                ymd = "{}{}{}".format(file_date.year, str(file_date.month).zfill(2), str(file_date.day).zfill(2))
                if precision == 'hour':
                    t_key = "{}{}".format(ymd, str(file_date.hour).zfill(2))
                elif precision == 'minute':
                    t_key = "{}{}{}".format(ymd, str(file_date.hour).zfill(2), str(file_date.minute).zfill(2))
                else:
                    return False
                if t_key not in merge_list.keys():
                    merge_list[t_key] = list()
                # 若网卡在合并列表内，则合并
                if i in ifs:
                    if not os.popen('/usr/sbin/lsof {}'.format(os.path.join(root, file))).read():
                        merge_list[t_key].append(os.path.join(root, file))

    for time, f in merge_list.items():
        if len(f) > 1:
            files_str = ' '.join(f)
            target_file = os.path.join(dir_path, 'merged', 'wirecap_{}.pcap'.format(time))
            used_dir = os.path.join(dir_path, 'used')
            merge_result = os.popen('mergecap -a {} -w {}'.format(files_str, target_file))
            logger.info("merge result: {}".format(merge_result))
            if packets_validation(f, target_file):
                for used_file in f:
                    os.system('mv {} {}'.format(used_file, used_dir))
            else:
                logger.error('Source packets is not equal to merged pcap file')
                logger.error('Source file: ' + str(f))
                logger.error('Target file: ' + target_file)
    return None


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


if __name__ == "__main__":
    # 读入参数
    cfg = parsArgs()

    # 初始化schedule
    sc = ScheduleCap()

    # global config
    store_path = cfg.get('store_path', "/data/tcpdump")
    reserve = cfg.get('reserve', 60)
    global_cpu = cfg.get('cpu', 6)
    mergecap = cfg.get('mergecap', 1)
    log_path = cfg.get('log_path', "/var/log/tcpdump")
    remote_dir = cfg.get('remote_dir')
    rotate_percent = cfg.get('rotate_percent', 90)
    date_format = cfg.get('date_format', "%Y%m%d-%h%m")
    precision = cfg.get('precision', 'minute')

    merged_path = os.path.join(store_path, 'merged')
    used_path = os.path.join(store_path, 'used')

    # 检查目标文件夹，不存在则创建
    for path in (store_path, merged_path, log_path, used_path):
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
        cpu = job.get('cpu', global_cpu)
        for s in schedules:
            trigger = s.get('trigger')
            s_second, s_minute, s_hour, s_day, s_month, s_week = s.get('start').split()
            e_second, e_minute, e_hour, e_day, e_month, e_week = s.get('end').split()
            start_kwargs = {
                'func': cap,
                'trigger': trigger,
                'second': int(s_second) if not re.search(r"\*", s_second) else None,
                'minute': int(s_minute) if not re.search(r"\*", s_minute) else None,
                'hour': int(s_hour) if not re.search(r"\*", s_hour) else None,
                'day': int(s_day) if not re.search(r"\*", s_day) else None,
                'month': int(s_month) if not re.search(r"\*", s_month) else None,
                'day_of_week': s_week if s_week else None,
                'args': [interface, store_path, params, cpu, date_format]
            }

            end_kwargs = {
                'func': kill_proc,
                'trigger': trigger,
                'second': int(e_second) if not re.search(r"\*", e_second) else None,
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
        print(monitor)
        _kwargs = dict()
        trigger = monitor['schedules']['trigger']
        t_dict = dict()
        t_dict['minutes'], t_dict['hours'], t_dict['days'], t_dict['months'], t_dict['weeks'] = monitor['schedules'][
            'wait'].strip().split()

        _kwargs['trigger'] = trigger
        for t in ('minutes', 'hours', 'days', 'months', 'weeks'):
            if t_dict[t] != '*':
                _kwargs[t] = eval(t_dict[t])

        if monitor.get('item') == "time":
            pass

        if monitor.get('item') == "rotate":
            _kwargs['func'] = rotate
            _kwargs['args'] = [store_path, reserve, rotate_percent, remote_dir]

        if monitor.get('item') == "merge":
            _kwargs['func'] = merge_files
            _kwargs['args'] = [store_path, monitor_interface, date_format, precision]

        if _kwargs:
            print(_kwargs)
            sc.add(**_kwargs)

    print(sc.scheduler.get_jobs())

    sc.start_cap()
