#!/usr/bin/python
# -*- coding: UTF-8 -*-
# Copyright (c) 2018  Keyone (blog:http://www.key1.top)

import sys
import os
import getopt
import xml.dom.minidom
import sqlite3

VERSION = "1.1"
DEFAULT_DATABASE = "./nmap_scan.db" #默认sqlite数据库

true = 1
false = 0


def usage(name):
    print "usage: %s [options] <nmap output XML file(s)>" % name
    print "options:"
    print "     (-h) --help         显示帮助菜单"
    print "     (-c) --create       创建初始化SQLite数据库"
    print "     (-d) --database     指定导出的SQLite数据库"
    # print "     (-n) --nodb         不执行任何数据库操作(预演习)"
    print "     (-v) --version      输出版本信息并退出"
    print "==============使 用 样 例====================="
    print "1.创建初始化数据库: "
    print "./nmap2sqlite.py -c sqlite.sql -d scan.db"
    print "2.将多个XML文件内容导入相同数据库: "
    print "./nmap2sqlite.py -d scan.db host.xml host2.xml host3.xml ..."


    return

def main(argv, environ):
    nodb_flag = false
    db_path = DEFAULT_DATABASE
    sql_file = ""
    argc = len(argv)

    if argc == 1:
        usage(argv[0])
        sys.exit(0)
 
    try:
        # alist, args = getopt.getopt(argv[1:], "h:d:c:nv",
        #         ["help", "database=", "create=",
        #          "nodb", "version"])
        alist, args = getopt.getopt(argv[1:], "h:d:c:v",
                ["help", "database=", "create=", "version"])
    except getopt.GetoptError, msg:
        print "%s: %s\n" % (argv[0], msg)
        usage(argv[0]);
        sys.exit(1)
 
    for(field, val) in alist:
        if field in ("-h", "--help"):
            usage(argv[0])#显示帮助菜单
            sys.exit(0)
        if field in ("-d", "--database"):
            db_path = val#指定数据库
        if field in ("-c", "--create"):
            sql_file = val#创建数据库
        if field in ("-n", "--nodb"):
            nodb_flag = true #预演习
        if field in ("-v", "--version"):
            print "nmapdb v%s by ICS" % (VERSION)
            print "parse nmap's XML output files and insert them into an SQLite database"
            sys.exit(0)


    if nodb_flag == false:
        if db_path == DEFAULT_DATABASE:
            print "%s: no output SQLite DB file specified, using \"%s\"\n" % (argv[0], db_path)

        conn = sqlite3.connect(db_path)#连接SQLite数据库
        cursor = conn.cursor()


    if nodb_flag == false:
        if sql_file != "":
            sql_string = open(sql_file, "r").read() #打开目录下.sql文件，创建数据库
            try:
                cursor.executescript(sql_string) #执行sql文件内容
            except sqlite3.ProgrammingError, msg:
                print "%s: error: %s\n" % (argv[0], msg)
                sys.exit(1)

    for fname in args:
        try:
            doc = xml.dom.minidom.parse(fname) #用minidom解析器打开XML文档
        except IOError:
            print "%s: error: file \"%s\" doesn't exist\n" % (argv[0], fname)
            continue
        except xml.parsers.expat.ExpatError:
            print "%s: error: file \"%s\" doesn't seem to be XML\n" % (argv[0], fname)
            continue


        #########以下是获取host信息#######
        for host in doc.getElementsByTagName("host"):#查找host节点

            try:
                status = host.getElementsByTagName("status")[0] #查找主机状态(host.status节点)
                state = status.getAttribute("state")
            except:
                state = ""

            try:
                address = host.getElementsByTagName("address")[0] #查找IP地址信息(host.address节点)
                ip = address.getAttribute("addr")
                protocol = address.getAttribute("addrtype")
            except:
                # move to the next host since the IP is our primary key
                continue

            try:
                mac_address = host.getElementsByTagName("address")[1] #查找MAC地址信息(host.address节点)
                mac = mac_address.getAttribute("addr")
                mac_vendor = mac_address.getAttribute("vendor")
            except:
                mac = ""
                mac_vendor = ""

            try:
                hname = host.getElementsByTagName("hostname")[0] #查找主机名信息(host.hostname节点)
                hostname = hname.getAttribute("name")
            except:
                hostname = ""

            try:
                os_el = host.getElementsByTagName("os")[0] #查找OS信息

                os_match = os_el.getElementsByTagName("osmatch")[0] # os.osmatch节点
                os_name = os_match.getAttribute("name")     # os名称
                os_accuracy = os_match.getAttribute("accuracy")  # 准确率

                os_class = os_el.getElementsByTagName("osclass")[0]
                os_family = os_class.getAttribute("osfamily")
                os_gen = os_class.getAttribute("osgen")
            except:
                os_name = ""
                os_accuracy = ""
                os_family = ""
                os_gen = ""

            try:
                timestamp = host.getAttribute("endtime") #　扫描结束时间
            except:
                timestamp = ""

            try:
                hostscript = host.getElementsByTagName("hostscript")[0]
                script = hostscript.getElementsByTagName("script")[0]
                id = script.getAttribute("id")

                if id == "whois":
                    whois_str = script.getAttribute("output")
                else:
                    whois_str = ""

            except:
                whois_str = ""


            #####将以上获取到的host信息插入sqlite数据库中的hosts表中#####
            if nodb_flag == false:
                try:
                    cursor.execute("INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (ip, mac, hostname, protocol, os_name, os_family, os_accuracy,
                            os_gen, timestamp, state, mac_vendor, whois_str))
                except sqlite3.IntegrityError, msg:
                    print "%s: warning: %s: table hosts: ip: %s\n" % (argv[0], msg, ip)
                    continue
                except:
                    print "%s: unknown exception during insert into table hosts\n" % (argv[0])
                    continue




            #########以下是获取port信息#######
            try:
                ports = host.getElementsByTagName("ports")[0]  # host.ports节点
                ports = ports.getElementsByTagName("port")     # host.ports.port节点
            except:
                print "%s: host %s has no open ports\n" % (argv[0], ip)
                continue

            for port in ports:
                pn = port.getAttribute("portid")                # 获取端口信息
                protocol = port.getAttribute("protocol")
                state_el = port.getElementsByTagName("state")[0]
                state = state_el.getAttribute("state")

                try:
                    service = port.getElementsByTagName("service")[0] # host.ports.port.service节点
                    port_name = service.getAttribute("name")          # 获取端口对应服务信息
                    product_descr = service.getAttribute("product")
                    product_ver = service.getAttribute("version")
                    product_extra = service.getAttribute("extrainfo")
                except:
                    service = ""
                    port_name = ""
                    product_descr = ""
                    product_ver = ""
                    product_extra = ""
                    
                service_str = "%s %s %s" % (product_descr, product_ver, product_extra)

                info_str = ""

                for i in (0, 1):
                    try:
                        script = port.getElementsByTagName("script")[i] # host.ports.port.script节点
                        script_id = script.getAttribute("id")
                        script_output = script.getAttribute("output") # 获取NSE脚本运行打印的output信息
                    except:
                        script_id = ""
                        script_output = ""

                    if script_id != "" and script_output != "":
                        info_str += "%s: %s\n" % (script_id, script_output)


                #####将以上获取到的host信息插入sqlite数据库中的ports表中#####
                if nodb_flag == false:
                    try:
                        cursor.execute("INSERT INTO ports VALUES (?, ?, ?, ?, ?, ?, ?)", (ip, pn, protocol, port_name, state, service_str, info_str))
                    except sqlite3.IntegrityError, msg:
                        print "%s: warning: %s: table ports: ip: %s\n" % (argv[0], msg, ip)
                        continue
                    except:
                        print "%s: unknown exception during insert into table ports\n" % (argv[0])
                        continue


    if nodb_flag == false:
        conn.commit()

if __name__ == "__main__":
    main(sys.argv, os.environ)
    sys.exit(0)

# EOF
