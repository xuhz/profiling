#! /usr/bin/env python

# Copyright (c) 2017 Huazhuo Xu.
# Licensed under the GNU General Public License, Version 2
#
# 03/20/2017 Huazhuo Xu  Created this.
#
# Functionality wise, this is the same to the previous perl verison of the
# post processing tool. In this python veriosn, an interactive mode is
# introduced. The motivation here is, most of the time we will check info
# multiple times against one profiling file or 2 files(diff). The setback
# of the perl version is, the program exits after each run, so when the file
# is large, each new run will read the file from disk from scratch. It is
# very slow. With the new interactive mode, the files are loaded into memory
# and kept open, so all subsequent processes against the opened files would
# be fast.
#
# post-kp.py -h will show the usage info and some examples.
# 
# The input profiling file can be from perf, dtrace, systemtap output, or
# ebpf.
#
# Take perf as instance, the profiling file can be achieved in this way,
# >perf record -a -g -F 479 sleep 30
# >perf script |./perfconvert.pl > perf.kpstk
# here,
# -a means profiling against all cpus, if only specific cpus are
# desired, -C cpus can be used instead.
# 
# -g means call stacks are collect.
#
# -F 479 is the sample frequency -- 479 per second. Node, the default event
# used by perf is cpu cycles, so once the sample frequency is selected, perf
# will calculate how many cpu cycles triggering a HW counter overflow interrupt
# can best match the sample frequency. This number is not that accurate. By
# contrast, the -c option is accurate, which is used to specify how many exact
# cpu cycles will trigger a overflow. Eg. on a 4G cpu clock freq machine, there
# are 4 billion cycles per second, so -F 479 is equivalent to -c 8000000
#
# sleep 30 means profiling lasts 30 seconds.
#
# I also tried ebpf on ubuntu 17.04 zesty. It can be used almost the same way.
# >./profile.ebpf 30 > bfp.kp
#
# More explaination, refer to post-kp.pl
#
# post-kp.py
# Huazhuo(Brian) Xu
# xuhuazhuo@gmail.com

from __future__ import print_function
import sys
import re
import os
import argparse
import textwrap

version="version 1.0"

class doit(object):
	def __init__(self,args):
		"""
		files: fd /type if list
		fmap: file name -> fd /dict
		handle: index of opened files which are now active /list
		fname: file name of opened files which are now active /list
		total: number of samples for each file /list
		incl: inclusive of each func for each file /dict list
		excl: exclusive /dict list
		caller_callee: each individual stack for each file /dict list
		inst: instruction level of each func for each file /dict list
		excldiff: exclusive difference between 2 files /list
		instdiff: instruction difference between 2 files /list
		incldiff: inclusive difference between 2 files /list
		lines: lines to display for the subcmd. Default 20
		depth: call stack depth to show for caller
		"""
		self.files=[]
		self.incl=[]
		self.excl=[]
		self.inst=[]
		self.caller_callee=[]
		self.coalesce=[]
		self.total=[]
		self.incldiff={}
		self.excldiff={}
		self.instdiff={}
		self.fmap={}
		self.handle=[]
		self.fname=[]
		self.lines=args.lines
		self.depth=args.depth
		self.openfile(args.files)

	def listfile(self):
		"""
			List opened files and active files.
			opened files: all those opened and loaded profiling files
			active files: 1 or 2. Default files being worked on if not
						  specified
		"""
		print("Opened file(s):")
		for f in self.fmap:
			print('\t%s'%(self.files.index(self.fmap[f])),end=':')
			print(f)
		print("active file(s):")
		for i in range(len(self.handle)):
			print('\t%s'%(self.handle[i]),end=':')
			print(self.fname[i])

	def openfile(self,files):
		"""
			Open the profiling files
		"""
		for f in files:
			if f in self.fmap:
				continue
			try:
				fd=open(f,'r');
				self.files.append(fd)
				self.fmap[f]=fd
				if len(self.handle)<2:
					self.handle.append(len(self.files)-1)
					self.fname.append(f)
				self.total+=[0]
				self.inst+=[{}]
				self.excl+=[{}]
				self.incl+=[{}]
				self.caller_callee+=[{}]
				self.loadfile(fd)
			except IOError:
				pass
				print('%s not exist!!'%(f))

	def loadfile(self,fd):
		"""
			Scan profiling file and extract both function level and
			instruction level info from call stacks.
		"""
		pat=re.compile(r'!')
		f=self.files.index(fd)
		index=0
		newstack=0
		fnc={}
		inc={}
		thisline=[]
		for line in fd:
			line=line.strip()
			if pat.search(line):
				if newstack>0 and index>1:
					count=int(thisline[index-1])
					for i in range(index-1):
						fn=thisline[i]
						fn=re.sub('^.*[: |`]','',fn)
						fn=re.sub('\/.*$','',fn)
						inc[fn]=inc.get(fn,0)+1
						fn=re.sub('\+.*$','',fn)
						fnc[fn]=fnc.get(fn,0)+1
						if i==0:
							self.excl[f][fn]=self.excl[f].get(fn,0)+count
						else:
							fn=fn+"+"+prefunc
						prefunc=fn
					self.total[f]+=count
					for i in fnc:
						self.incl[f][i]=self.incl[f].get(i,0)+count*fnc[i]
					for i in inc:
						self.inst[f][i]=self.inst[f].get(i,0)+count*inc[i]
					self.caller_callee[f][fn]=self.caller_callee[f].get(fn,0)+count
					fnc.clear()
					inc.clear()
					del thisline[:]
					index=0

				newstack+=1
				continue

			if newstack>0:
				thisline += [line]
				index+=1

	def getdiff(self,din1,n1,din2,n2,dout):
		"""
			Get diffs from 2 inputs.
			args:
				dinx: input dictionary x
				nx: total number of samples for x
				dout: output dictionary
			Since samples in file1 and file2 may be(and always are) different,
			only percentage makeks sense.
		"""
		for k in din1:
			if k in din2:
				dout[k]=100.0*din2[k]/n2-100.0*din1[k]/n1
			else:
				dout[k]=0-100.0*din1[k]/n1
		for k in din2:
			if k not in dout:
				dout[k]=100.0*din2[k]/n2

	def instruction(self, fn):
		"""
			Handle instruction level info within function.
			Most of the time, we are more interested in function level
			info, so all IPs within function are coalesced. In some cases,
			instruction level info is more useful. Eg. Memory access cache
			miss and atomic instruction are expensive. Instruction level
			helps in order to identify those.
		"""
		print("---------------------non-coalesce function----------------")
		if len(self.handle)==1:
			f0=self.handle[0]
			lst=sorted(self.inst[f0].items(), key=lambda (k,v):v,reverse=True)
		else:
			f0=self.handle[0]
			f1=self.handle[1]
			if not self.instdiff:
				self.getdiff(self.inst[f0],self.total[f0],
						self.inst[f1],self.total[f1],
						self.instdiff)
			lst=sorted(self.instdiff.items(), key=lambda (k,v):v,reverse=True)
			title='\t\t\t%s\t%s\tDiff' % (self.fname[0],self.fname[1])
			print(title)
		count=0
		for i in lst:
			(k,v)=i[0],i[1]
			fns=i[0].strip().split('+')
			if fns[0]==fn and count<= self.lines:
				count+=1
				if len(self.handle)==1:
					row='%-20s\t%6.2f%%(%d)' % (k,100.0*v/self.total[f0],v)
				else:
					pct1=self.pct_helper(k,self.inst[f0],self.total[f0])
					pct2=self.pct_helper(k,self.inst[f1],self.total[f1])
					row='%-20s %6.2f%%\t%6.2f%%\t%6.2f%%' % (k,pct1,pct2,v)
				print(row)

	def pct_helper(self,k,d,total):
		"""
			helper function to calculate the percentage of a function or stack.
			if the specified func doesn't exist, return -100%
		"""
		if k in d:
			return 100.0*d[k]/total
		else:
			return -100.0

	def cc_helper(self, cmd, fn, f):
		"""
			helper function of cc(). It extracts from all stacks the ones 
			which contains the specified 'fn', and saves the caller or callee 
			info to a dictionary.
			args:
				cmd: "caller" or "callee"
				fn: function specified
				f: the active file
			return: a dictionary

			For caller, if the fn is the bottom one on the stack,
			show "bottom_of_stack"
			For callee, if the fn is the top one one the stack,
			show "top_of_stack". Actually it is exactly the exclusive
			number of the function.
		"""
		cc=dict()
		for stk in self.caller_callee[f]:
			stk=stk.strip()
			fns=stk.split('+')
			count=fns.count(fn)
			if count==0:
				continue;
			if count>1:
				print("Note: recursive!")
			i=fns.index(fn)
			if cmd=="caller":
				if i>0:
					if i+1>self.depth:
						key='+'.join(fns[i-self.depth:i+1])
					else:
						key='+'.join(fns[:i+1])
				else:
					key="bottom_of_stack!+"+fns[0]
			if cmd=="callee":
				if i!=len(fns)-1:
					key=fns[i]+"+"+fns[i+1]
				else:
					key="top_of_stack!"
			cc[key]=cc.get(key,0)+self.caller_callee[f][stk]*count

		return cc

	def cc(self, cmd, fn):
		"""
			Handle caller and callee. Depend on the number of active
			files(1 or 2), it displays the info of 1 file, or the diff of 2 
			files.
					
			args:	
				cmd: "caller" or "callee"
				fn: the function specified

				"caller":
					Show calling functions or stacks of the specified 'fn'
				"callee":
					Show called functions of the specified 'fn'
			
			Only the "caller" can show stacks, '-s' is used to specified
			depth of the stack to show.
		"""
		cc={}
		if len(self.handle)==1:
			f0=self.handle[0]
			if fn not in self.incl[f0]:
				warning='%s not exist!!' % (fn)
				print(warning)
				return
			cc=self.cc_helper(cmd,fn,f0)
		else:
			f0=self.handle[0]
			f1=self.handle[1]
			if fn not in self.incl[f0] and fn not in self.incl[f1]:
				warning='%s not exist!!' % (fn)
				print(warning)
				return
			cc0=self.cc_helper(cmd,fn,f0)
			cc1=self.cc_helper(cmd,fn,f1)
			self.getdiff(cc0,self.total[f0],cc1,self.total[f1],cc)
		lst=sorted(cc.items(), key=lambda (k,v):v,reverse=True)
		if cmd=="caller":
			print("-----------------Caller-------------------")
			if len(self.handle)>1:
				title='\t\t\t%s\t\t%s\t\tDiff' % (self.fname[0],self.fname[1])
				print(title)
			for i in range(min(self.lines,len(lst))):
				(k,v)=lst[i][0],lst[i][1]
				fns=k.strip().split('+')
				if len(self.handle)>1:
					pct1=self.pct_helper(k,cc0,self.total[f0])
					pct2=self.pct_helper(k,cc1,self.total[f1])
					row='%-20s\t%6.2f%%\t%6.2f%%\t%6.2f%%' % (fns[len(fns)-1],
						pct1,pct2,v)
				else:
					row='%-20s %6.2f%%(%d)' % (fns[len(fns)-1],
						 100.0*v/self.total[f0],v)
				print(row)
				for j in range(len(fns)-2,-1,-1):			
					row='%-30s' % (fns[j])
					print(row)
				print("------------------------------------------")
		if cmd=="callee":
			print("-----------------Callee-------------------")
			if len(self.handle)>1:
				in_pct1=self.pct_helper(fn,self.incl[f0],self.total[f0])
				ex_pct1=self.pct_helper(fn,self.excl[f0],self.total[f0])
				in_pct2=self.pct_helper(fn,self.incl[f1],self.total[f1])
				ex_pct2=self.pct_helper(fn,self.excl[f1],self.total[f1])
				row='%s\t%s(in:%6.2f%% ex:%6.2f%%)\t%s(in:%6.2f%% ex:%6.2f%%)'%(
					fn,
					self.fname[0],in_pct1,ex_pct1,
					self.fname[1],in_pct2,ex_pct2)
			else:
				in_pct1=self.pct_helper(fn,self.incl[f0],self.total[f0])
				ex_pct1=self.pct_helper(fn,self.excl[f0],self.total[f0])
				row='%-20s\tin:%6.2f%%(%d)\tex:%6.2f%%(%d)' % (fn,
					in_pct1,self.incl[f0][fn] if fn in self.incl[f0] else 0,
					ex_pct1,self.excl[f0][fn] if fn in self.excl[f0] else 0)
			print(row)
			print("------------------------------------------")
			if len(self.handle)>1:
				title='\t\t\t%s\t\t%s\t\tDiff' % (self.fname[0],self.fname[1])
				print(title)
			for i in range(min(self.lines,len(lst))):
				(k,v)=lst[i][0],lst[i][1]
				fns=k.strip().split('+')
				if len(self.handle)>1:
					pct1=self.pct_helper(k,cc0,self.total[f0])
					pct2=self.pct_helper(k,cc1,self.total[f1])
					row='  --> %-20s %6.2f%% %6.2f%% %6.2f%%' % (fns[-1],
						 pct1,pct2,v)
				else:
					row='  --> %-20s %6.2f%%(%d)' % (fns[-1],
						 100.0*v/self.total[f0],v)
				print(row)
	

	def ie(self,cmd):
		"""
			Handle inclusive and/or exclusive. Depend on the number of active
			files(1 or 2), it displays the info of 1 file, or the diff of 2 
			files.

			args:
				cmd: "in", "ex", "ina", "exa"	
				"in":
					Show inclusive in decending order
				"ex":
					Show exclusive in decending order
				"ina":
					Show both inclusive and exclusive in inclusive decending order
				"exa":
					Show both inclusive and exclusive in exclusive decending order
			
			In diff mode(2 active files), only "in" and "ex" are supported. So
			if you run like,
			(file1, file2)>ina
			only the in & ex info of 1st file is displayed.
		"""
		if len(self.handle)==1:
			f0=self.handle[0]
			if cmd=="in":
				title="Function\t\t\tInclusive"
				lst=sorted(self.incl[f0].items(), key=lambda (k,v):v,reverse=True)
			if cmd=="ex":
				title="Function\t\t\tExclusive"
				lst=sorted(self.excl[f0].items(), key=lambda (k,v):v,reverse=True)
		else:		
			f0=self.handle[0]
			f1=self.handle[1]
			if not self.incldiff:
				self.getdiff(self.incl[f0],self.total[f0],
						self.incl[f1],self.total[f1],
						self.incldiff)
				self.getdiff(self.excl[f0],self.total[f0],
						self.excl[f1],self.total[f1],
						self.excldiff)
			if cmd=="in":
				print("--Inclusive--")
				title='Function\t\t\t%s\t%s\tDiff' % (self.fname[0],self.fname[1])
				lst=sorted(self.incldiff.items(), key=lambda (k,v):v,reverse=True)
			if cmd=="ex":
				print("--Exclusive--")
				title='Function\t\t\t%s\t%s\tDiff' % (self.fname[0],self.fname[1])
				lst=sorted(self.excldiff.items(), key=lambda (k,v):v,reverse=True)
		if cmd=="ina": 
			title="Function\t\t\tInclusive\tExclusive"
			lst=sorted(self.incl[f0].items(), key=lambda (k,v):v,reverse=True)
		if cmd=="exa": 
			title="Function\t\t\tInclusive\tExclusive"
			lst=sorted(self.excl[f0].items(), key=lambda (k,v):v,reverse=True)
		print(title)
		for i in range(min(len(lst),self.lines)):
			(k,v)=lst[i][0],lst[i][1]
			if cmd=="in" or cmd=="ex":
				if len(self.handle)>1:
					if cmd=="in":
						pct1=self.pct_helper(k,self.incl[f0],self.total[f0])
						pct2=self.pct_helper(k,self.incl[f1],self.total[f1])
					else:
						pct1=self.pct_helper(k,self.excl[f0],self.total[f0])
						pct2=self.pct_helper(k,self.excl[f1],self.total[f1])
					row='%-30s%6.2f%%\t\t%6.2f%%\t\t%6.2f%%' % (k,pct1,pct2,v)
				else:
					row='%-30s %6.2f%%(%d)' % (k,100.0*v/self.total[f0],v)
			elif cmd=="ina":
				exv=self.excl[f0][k] if k in self.excl[f0] else 0
				row='%-30s %6.2f%%(%d)\t%6.2f%%(%d)' % (k,
					100.0*v/self.total[f0],v,
					100.0*exv/self.total[f0], exv)
			else:
				inv=self.incl[f0][k] if k in self.incl[f0] else 0
				row='%-30s %6.2f%%(%d)\t%6.2f%%(%d)' % (k,
					100.0*inv/self.total[f0], inv,
					100.0*v/self.total[f0], v)
			print(row)

	def go(self,args):
		"""Second level entry of execution"""

		desc0=textwrap.dedent('''\
			No file(s) opened
			''')
		help0=textwrap.dedent('''\
			subcommand:
				open: open files
				quit: exit
				help: print usage
			''')
		parser0=argparse.ArgumentParser(description=desc0, epilog=help0,
        	formatter_class=argparse.RawDescriptionHelpFormatter)
		parser0.add_argument('cmd', nargs='*', type=str)

		desc1=textwrap.dedent('''\
			file(s) opened
			''')
		help1=textwrap.dedent('''\
			subcommand:
				quit: exit
				open: open more files
					open file1 [file2 [file3 ...]]
				ls:  list opened file and active files
				help: print usage
				in : print inclusive of one file or diff of two files 
					in [-f file1 [file2]] [-n lines]
				ex : print exclusive of one file or diff of two files
					ex [-f file1 [file2]] [-n lines]
				ina : print in & ex of one file, sorted by inclusive
					ina [-f file1] [-n lines]
				exa : print in & ex of one file, sorted by exclusive
					exa [-f file1 [file2]] [-n lines]
				caller : print call stack to 'fn' 
					caller [-f file1 [file2]] [-n lines] [-s depth] fn
				callee : print functions called by 'fn'
					callee [-f file1 [file2]] [-n lines] fn
				func : print expensive instructions with 'fn'
					func [-f file1 [file2]] [-n lines] fn
			options:
				-n : number of lines displayed
				-s : depth of call stack
				-f : file to operate on(-f file1, or -f file1 -f file2)

			Notes:
				Profiling files need to be opened first before any kind of
				post processing can be done. In theory, there is not limit
				by this tool itself on the number of files opened. Keeping
				the file open is very convenient when the files are pretty
				large since the pre-processed files are saved in memory, so
				all subsequent processes are fast.

				Active files are those subcmds operate on if '-f' is not
				specified by the subcmd. Active files must be subset of
				opened files. There are at least 1 and at most 2 active files.
				If there is 2, all those subcmds which need files are working
				in diff mode -- the difference between 2 files is displayed.
				By default, active files are the first 2 files opened. Then
				afterwards, if any subcmd specifies '-f' opention, the file(s)
				becomes the active one(s)

				'ls' subcmd lists all opened and active files. 
			''')

		subcmd=['quit','ls','help','open','in','ex','ina','exa','caller',
				'callee','func']
		def print_help(errmsg):
			print(errmsg)
		def addargs(subparser,cmd,add_fn):
			if add_fn:			
				subparser.add_argument("fn",nargs=1)
			subparser.add_argument("-n","--lines", type=int, default=20)
			subparser.add_argument("-s","--depth", type=int, default=1)
			subparser.add_argument("-f","--files", nargs='+', type=str)
			subparser.set_defaults(func=cmd)

		parser1=argparse.ArgumentParser(description=desc1, epilog=help1,
        	formatter_class=argparse.RawDescriptionHelpFormatter)
		parser1.error=print_help
		parser1.exit=print_help
		subparsers=parser1.add_subparsers(help=help1)
		sub_quit=subparsers.add_parser('quit')
		sub_quit.set_defaults(func='quit')
		sub_help=subparsers.add_parser('help')
		sub_help.set_defaults(func='help')
		sub_ls=subparsers.add_parser('ls')
		sub_ls.set_defaults(func='ls')
		sub_open=subparsers.add_parser('open')
		sub_open.add_argument('files',nargs='+')
		sub_open.set_defaults(func='open')
		sub_caller=subparsers.add_parser('caller')
		addargs(sub_caller,"caller",1)
		sub_callee=subparsers.add_parser('callee')
		addargs(sub_callee,"callee",1)
		sub_func=subparsers.add_parser('func')
		addargs(sub_func,"func",1)
		sub_in=subparsers.add_parser('in')
		addargs(sub_in,"in",0)
		sub_ex=subparsers.add_parser('ex')
		addargs(sub_ex,"ex",0)
		sub_ina=subparsers.add_parser('ina')
		addargs(sub_ina,"ina",0)
		sub_exa=subparsers.add_parser('exa')
		addargs(sub_exa,"exa",0)
		while 1:
			while len(self.files)==0:
				print("kp", end='>')
				#line = sys.stdin.readline().strip()
				line = raw_input()
				args0=parser0.parse_args(line.split())
				splt=args0.cmd
				if len(splt)==0:
					continue
				elif splt[0]=="quit":
					exit(0)
				elif splt[0]=="help":
					print(help0, end='')
				elif splt[0]!="open":
					continue
				self.openfile(splt[1:])
				args.interactive=True
				break

			while len(self.files)!=0:
				if len(self.fname)>1:
					prompt='(%s,%s)'%(self.fname[0],self.fname[1])
				else:
					prompt='(%s)'%(self.fname[0])
				print(prompt, end='>')
				line = raw_input().split()
				if len(line)<1:
					continue
				if line[0] not in subcmd:
					print('\'%s\' unknown!!'%(line[0]))
					continue
				args1,unknown=parser1.parse_known_args(line)
				if unknown:
					print('%s unknown. Omitted!'%(unknown))
				cmd=args1.func
				if cmd=="quit":
					exit(0)
				elif cmd=="help":
					print(help1, end='')
				elif cmd=="ls":
					self.listfile()
				elif cmd=="open":
					if args1.files is not None:
						self.openfile(args1.files)
				else:
					if args1.files is not None:
						class InvalidFile(Exception): pass
						try:
							for i,v in enumerate(args1.files):
								if v.isdigit() and 0<=int(v)<len(self.files):
									for k in self.fmap:
										if self.fmap[k]==self.files[int(v)]:
											v=k
											args1.files[i]=k
											break
								if v not in self.fmap:
									print('%s not opened yet, open it first!'%(v))
									raise InvalidFile
						except InvalidFile:
							pass
							continue
						self.handle=[]
						self.fname=[]
						self.incldiff={}
						self.excldiff={}
						self.instdiff={}
						for i in args1.files:
							if len(self.handle)<2:
								self.handle.append(self.files.index(self.fmap[i]))
								self.fname.append(i)
					self.lines=args1.lines
					self.depth=args1.depth
					if cmd in ["in","ex","ina","exa"]:
						self.ie(cmd)
					if cmd in ["caller","callee"]:
						self.cc(cmd,args1.fn[0])
					if cmd=="func":
						self.instruction(args1.fn[0])
				
def main():
	"""Top levelry of execution"""
	desc=textwrap.dedent('''\
		Post processing perf/stap/dtrace profiling data. 
		Examples:
			1. post-kp.py -h
				print usage info
			2. post-kp.py or post-kp.py -i
				interactive mode. waiting for profiling files to be opened
				interactive mode is usefull when the file is huge since the
				file keeps open and all data has been read in memory, and
				multiple cmds need to be run against the file
			3. post-kp.py file1
				list the inclusive of functions in sorted order By default, 
				only the first 20 functions are displayed. -n can be used to
				specify any numbers. 
			4. post-kp.py file1 file2
				list the inclusive difference of fuctions in sorted order 
				between file1 and file2.
			6. post-kp.py -i file1 file2 file3
				open all files, then wait for subcommand.
			7. post-kp.py -C fn file1
				list all call stacks to fn. -s is used to specify depth of
				stack to show
			8. post-kp.py -C fn file1 file2
				list call stack diference to fn between file1 and file2
			9. post-kp.py -c fn file1
				list all functions fn calls
			10. post-kp.py -f fn file1
				list all expensive instructions in fn
		''')
	help=textwrap.dedent('''\
		Usage:
			post-kp.py [-i]
			post-kp.py [-v]
			post-kp.py [-t type] [-n lines] [-i] file1,file2...,filen
			post-kp.py [-Ccf fn] [-s depth] [-n lines] file1, file2
		''')

	parser=argparse.ArgumentParser(description=desc, epilog=help,
        formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("files", nargs='*', help="input file(s)")
	parser.add_argument("-t","--type", choices=['in','ex','ina','exa'], default='in')
	parser.add_argument("-C","--caller", help="print caller(s) of the function",
						type=str)
	parser.add_argument("-c","--callee", help="print callee(s) of the function",
						type=str)
	parser.add_argument("-f","--func", help="print expensive instrutions in func",
						type=str)
	parser.add_argument("-n","--lines", help="print first n lines", type=int,
						default=20)
	parser.add_argument("-s","--depth", help="print first n lines", type=int,
						default=1)
	parser.add_argument("-i","--interactive", help="interactive mode",
						action="store_true")
	parser.add_argument("-v","--version", help="version", action="store_const",
						const=version)
	args=parser.parse_args()
	if args.version:
		print(args.version)
		return
	handle=doit(args)
	if args.interactive or not args.files:
		handle.go(args)
	else:
		if args.caller:
			handle.cc("caller",args.caller)
		elif args.callee:
			handle.cc("callee",args.callee)
		elif args.func:
			handle.instruction(args.func)
		else:
			handle.ie(args.type)
		
main()
