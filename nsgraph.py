# Netscaler config parser
# generates a graph of the objects defined in the config.ns file
# outputs a DOT and a PDF files; the DOT file can be manually modified
# requires graphviz
#
# Netscaler object names with spaces not supported
#
# v0.1 July 14, 2016
# santamariar@un.org


import pprint
import sys
import getopt
import string
import pygraphviz as pgv
import re

RE_GOOD_CHARS = '[^A-Za-z0-9/:()_-]+'
RE_NAME_CHARS = '[^A-Za-z0-9_-]+'
FORMATS = ['pdf', 'jpg', 'png', 'gif', 'svg', 'gv']

config_file = ""
output_file = ""
view_file = False
view_not_processed = False
view_source = False
reduce_vip = ""

all_lines = []
not_processed = []
summary = {}
summary['vip'] = set()
summary['srv'] = set()
summary['svc'] = set()
summary['svcgrp'] = set()
summary['lbvs'] = set()
summary['csvs'] = set()
summary['act'] = set()
summary['pol'] = set()
summary['cert'] = set()
summary['vpn'] = set()

def read_conf(config_file):
        g = pgv.AGraph(name="ns", directed=True)
        g.graph_attr.update(rankdir="LR")
        g.node_attr.update(shape="record", fontname="arial")
        with open(config_file) as cfile:
                for l in cfile:
                        all_lines.append(l)
                        f = string.split(l)
                        if "add server" in l:
                                summary['srv'].add(f[2])
                                g.add_node("srv-" + f[2],label=f[2] + " | " + f[3])
                        elif "add service" in l and not "add serviceGroup" in l:
                                summary['svc'].add(f[2])
                                g.add_node("svc-" + f[2],label=f[2] + " | " + f[4] + " | " + f[5])
                                g.add_edge("svc-"+f[2],"srv-"+f[3])
                        elif "add serviceGroup" in l:
                                summary['svcgrp'].add(f[2])
                                g.add_node("svcgrp-" + f[2],label=f[2] + " | " + f[3])
                        elif "bind serviceGroup" in l and not "monitorName" in l:
                                g.add_edge("svcgrp-"+f[2],"srv-"+f[3], label=f[4])
                        elif "add lb vserver" in l:
                                summary['lbvs'].add(f[3])
                                g.add_node("lbvs-"+f[3], label=lb_label(f))
                                if f[5] != "0.0.0.0":
                                        if not f[5] in summary['vip']:
                                                summary['vip'].add(f[5])
                                                g.add_node("vip-"+f[5])
                                        g.add_edge("vip-"+f[5],"lbvs-"+f[3],label=f[6])
                        elif "bind lb vserver" in l and not "-policyName" in l:
                                if f[4] in summary['svc']:
                                        g.add_edge("lbvs-"+f[3],"svc-"+f[4])
                                else:
                                        g.add_edge("lbvs-"+f[3],"svcgrp-"+f[4])
                        elif "add cs vserver" in l:
                                summary['csvs'].add(f[3])
                                g.add_node("csvs-"+f[3], label=f[3] + "|" + f[4] + "|" + f[5] + ":" + f[6])
                                if f[5] != "0.0.0.0":
                                        if not f[5] in summary['vip']:
                                                summary['vip'].add(f[5])
                                                g.add_node("vip-"+f[5])
                                        g.add_edge("vip-"+f[5],"csvs-"+f[3],label=f[6])
                        elif "add cs action" in l:
                                summary['act'].add(f[3])
                                g.add_node("act-" + f[3])
                                if "-targetLBVserver" in l:
                                        g.add_edge("act-"+f[3],"lbvs-"+f[5])
                        elif "add cs policy" in l:
                                summary['pol'].add(f[3])
                                g.add_node("pol-"+f[3],label=f[3] + " | rule:" + re.sub(RE_GOOD_CHARS,'',f[5]))
                                if "-action" in l:
                                        g.add_edge("pol-"+f[3],"act-"+f[f.index("-action")+1])
                        elif "add vpn vserver" in l:
                                summary['vpn'].add(f[3])
                                g.add_node("vpn-"+f[3], label=f[3] + "|" + f[4] + "|" + f[5] + ":" + f[6])
                                if f[5] != "0.0.0.0":
                                        if not f[5] in summary['vip']:
                                                summary['vip'].add(f[5])
                                                g.add_node("vip-"+f[5])
                                        g.add_edge("vip-"+f[5],"vpn-"+f[3],label=f[6])
                        elif "add vpn sessionAction" in l:
                                summary['act'].add(f[3])
                                label_vpn = f[3]
                                if "-wihome" in l:
                                        wi = f[ f.index("-wihome")+1 ]
                                        label_vpn += " | WI:" + wi
                                g.add_node('act-'+f[3],label=label_vpn)
                                if "-wihome" in l:
                                        try:
                                                wi_ip = re.search('/([0-9.]+)/',wi).group(1)
                                                g.add_edge('act-'+f[3], 'vip-'+wi_ip)
                                        except:
                                                pass
                        elif "add vpn sessionPolicy" in l:
                                summary['pol'].add(f[3])
                                g.add_node("pol-"+f[3], label=f[3] + " | rule:" + re.sub(RE_GOOD_CHARS,'',f[4]))
                                g.add_edge("pol-"+f[3], "act-"+f[5])
                        elif "bind vpn vserver" in l and "-staServer" in l:
                                g.add_edge("vpn-"+f[3], clean_name("sta-"+f[5]))
                        elif "bind vpn vserver" in l and "-policy" in l:
                                g.add_edge("vpn-"+f[3], "pol-"+f[5])
                        elif "add rewrite action" in l:
                                summary['act'].add(f[3])
                                g.add_node("rwact-" + f[3], label=f[3]+" | type:" + f[4] + " | " + re.sub(RE_GOOD_CHARS,'',f[5]) + " | " + re.sub(RE_GOOD_CHARS,'',f[6]))
                        elif "add rewrite policy" in l and not "policylabel" in l:
                                summary['pol'].add(f[3])
                                g.add_node("pol-"+f[3],label=f[3] + " | rule:" + re.sub(RE_GOOD_CHARS,'',f[4]))
                                g.add_edge("pol-"+f[3],"rwact-"+f[5])
                        elif "add responder action" in l:
                                summary['act'].add(f[3])
                                g.add_node("rsact-" + f[3], label=f[3]+" | type:" + f[4] + " | " + re.sub(RE_GOOD_CHARS,'',f[4]))
                        elif "add responder policy" in l and not "policylabel" in l:
                                summary['pol'].add(f[3])
                                g.add_node("pol-"+f[3],label=f[3] + " | rule:" + re.sub(RE_GOOD_CHARS,'',f[4]))
                                g.add_edge("pol-"+f[3],"rsact-"+f[5])
                        elif "bind cs vserver" in l:
                                if "-lbvserver" in l:
                                        g.add_edge("csvs-"+f[3],"lbvs-"+f[5], label="default")
                                elif "-policyName" in l and "-targetLBVserver" in l:
                                        g.add_edge("csvs-"+f[3],"pol-"+f[5],label="p="+f[9])
                                        g.add_edge("pol-"+f[5],"lbvs-"+f[7])
                                else:
                                        g.add_edge("csvs-"+f[3],"pol-"+f[5],label="p="+f[7])
                        elif "bind lb vserver" in l and "-policyName" in l:
                                g.add_edge("lbvs-"+f[3],"pol-"+f[5],label="p="+f[7])
                        elif "add ssl certKey" in l:
                                summary['cert'].add(f[3])
                                g.add_node("cert-"+f[3])
                        elif "link ssl certKey" in l:
                                g.add_edge("cert-"+f[3],"cert-"+f[4])
                        elif "bind ssl vserver" in l and "-eccCurveName" not in l and not "-cipherName" in l:
                                if f[3] in summary['lbvs']:
                                        g.add_edge("lbvs-"+f[3],"cert-"+f[5])
                                if f[3] in summary['csvs']:
                                        g.add_edge("csvs-"+f[3],"cert-"+f[5])
                                if f[3] in summary['vpn']:
                                        g.add_edge("vpn-"+f[3],"cert-"+f[5])
                        else:
                                not_processed.append(l)
        return g



def reduce(source, ip):
        g = pgv.AGraph(name="ns", directed=True)
        g.graph_attr.update(rankdir="LR")
        g.node_attr.update(shape="record", fontname="arial")
        if not source.has_node(ip):
                return g
        else:
                n = source.get_node(ip)
                g = get_neighbors(source, g, n)
        return g

def get_neighbors(source,target, node):
        if target.has_node(node):
                return target
        else:
                sub_target = target.copy()
                for n in source.successors_iter(node):
                        sub_target = get_neighbors(source,sub_target,n)
                sub_target.add_node(node, label=node.attr['label'])
                for e in source.out_edges_iter(node):
                        sub_target.add_edges_from([e])
                return sub_target




def lb_label(f):
        label=f[3] + "|" + f[4] + "|" + f[5] + ":" + f[6]
        if "-persistenceType" in f:
                label += "|persistence:" + f[f.index("-persistenceType")+1]
        if "-persistenceBackup" in f:
                label += "|persistenceBackup:" + f[f.index("-persistenceBackup")+1]
        if "-redirectURL" in f:
                label += "|redirect:" + f[f.index("-redirectURL")+1]
        if "-lbMethod" in f:
                label += "|lbMethod:" + f[f.index("-lbMethod")+1]
        return label

def clean_name(n):
        return re.sub(RE_NAME_CHARS,"",n)

def main(argv):
        config_file = ""
        output_file = ""
        view_file = False
        view_not_processed = False
        view_source = False
        output_format = 'jpg'
        reduce_vip = ""

        try:
                opts, args = getopt.getopt(argv,"c:o:f:usv:")
        except:
                usage()
                sys.exit(2)
        for opt, arg in opts:
                if opt == '-c':
                        config_file = arg
                if opt == '-o':
                        output_file = arg
                if opt == '-f':
                        output_format = arg
                if opt == '-u':
                        view_not_processed = True
                if opt == '-s':
                        view_source = True
                if opt == '-v':
                        reduce_vip = arg


        if config_file == "" or not output_format in FORMATS:
                usage()
                sys.exit(2)
        if output_file == "":
                output_file = config_file + "." + output_format

        print "Parsing config file " + config_file
        print "Exporting to file " + output_file

        graph = read_conf(config_file)
        print "File length: " + `len(all_lines)` + " lines."
        print "Not processed: " + `len(not_processed)` + " lines."
        if view_not_processed:
                print " "
                pprint.pprint(not_processed)
        if view_source:
                print " "
                print"" + graph.string()
                graph.write(config_file + ".dot")
        if reduce_vip != "":
                print "Reducing for VIP " + reduce_vip
                graph = reduce(graph, "vip-" + reduce_vip)
        print ""
        graph.draw(output_file, format=output_format, prog="dot")	



def usage():
        print "Usage: python nsparse.py -c configfile [-o outputfile] [-f format] [-u] [-s] [-v vip]"
        print "  -c    Input config.ns file."
        print "  -o    Output DOT file. The PDF file has the same name with .pdf extension"
        print "        If not specified, the input name is reused with .gv extension"
        print "  -f    Format; one of pdf, jpg, png, gif, svg or gv"
        print "  -u    Print unprocessed lines."
        print "  -s    Print graph source."
        print "  -v    Reduce a graph to only objects related to a VIP."

if __name__ == "__main__":
        main(sys.argv[1:])