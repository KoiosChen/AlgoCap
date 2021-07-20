import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import os
import configparser as cfp
from optparse import OptionParser
import multiprocessing

import configparser as cfp


def parsArgs():
    hstr = '%prog [options]'
    parser = OptionParser(hstr, version='%prog 0.1')
    parser.add_option("-c", "--config", dest="config", help="The local config path")
    parser.add_option("-i", "--interface", dest="interface", help="The interface to dump packets")

    (options, args) = parser.parse_args()

    print(options, args)

    if not options:
        parser.error("incorrect number of arguments")

    if options.config is None:
        parser.error("-c config file is required")

    if options.interface is None:
        parser.error("-n interface is required")

    return options, args


def getProp(options, args):
    filePath = '../dao/properties/prop.properties'  # 配置文件的相对路径
    cf = cfp.ConfigParser()
    cf.read(filePath)
    # 获取所有section，返回值为list
    print(cf.sections())
    # 获取属性名，返回一个属性名称list
    propName = cf.options('ORACLE')
    print(propName)
    # 获取属性名与属性值对
    kv = cf.items('ORACLE')
    print(kv)
    # 获取指定属性值
    val = cf.get('ORACLE', 'ORACLE_HOST')
    print(val)

    # 添加配置节点
    cf.add_section('other')
    cf.set('other', 'name', 'zhangsan')
    cf.write(open(filePath, 'w'))


def cdir(**kwargs):
    prefix = kwargs['prefix']
    interface = kwargs['interface']
    year = kwargs['year']
    month = kwargs['month']
    day = kwargs['day']
    path = os.path.join(prefix, interface, year, month, day)
    try:
        if not os.path.exists(path):
            os.mkdir(path)
        return path
    except Exception as e:
        raise Exception('mkdir {} failed for {}.'.format(path, str(e)))


def cap(iface, file_dir, params):
    now = datetime.datetime.now()
    ts = now.strftime('%Y%m%d-%H%M%S')
    print('do func time :', ts)
    dir_path = cdir(prefix=file_dir, interface=iface, year=now.year, month=now.month, day=now.day)
    file_path = os.path.join(dir_path, "wirecap_{}_{}.pcap".format(iface, ts))
    os.system('/usr/sbin/tcpdump -i {} -w {} {}'.format(iface, file_path, params))


def kill_proc():
    # 耗时2S
    now = datetime.datetime.now()
    ts = now.strftime('%Y-%m-%d %H:%M:%S')
    print('do func2 time：', ts)
    os.system('killall tcpdump')


class ScheduleCap:
    def __init__(self):
        self.scheduler = BlockingScheduler()

    def add_job(self, **kwargs):
        """

        :param kwargs:         func=start_cap,
                               trigger='cron',
                               second=00,
                               minute=45,
                               hour=16,
                               args=[iface, file_dir, params]
        :return:
        """
        self.scheduler.add_job(**kwargs)

    def start_cap(self):
        self.scheduler.start()


def merge_files():
    return None


if __name__ == "__main__":
    options, args = parsArgs()
    jobs = getProp(options, args)
    sc = ScheduleCap()
    for job in jobs:
        sc.add_job(**job)
    sc.start_cap()
    multiprocessing.Process(target=merge_files, )
