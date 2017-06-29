'''
#Rules

#str/flag/bool/bytes/output/entry/primaryKey
#cli_name: command line interface name (ex --all)
#flag: required; name, cli_name?, autofill, default
#* in name: multivalued
#str: name, cli_name?, alwaysask?
#bool: name, cli_name
#output: name, type[]

'command: ' <command>
'args: ' <arg.length> <option.length> <output.length>

'arg: ' a(opt_name, cli_name=par_name)
		a=str/...
'option: '  b(opt_name, c=bool, cli_name=opt_name, d)
			b=str/flag/...; c=alwaysask/autofill, d=default=?
'output: '  e(output_name, type=[<type f>])
			e=output/entry/..., f=type(ex. 'int', 'dict')

#Extras: 
#listOfPrimaryKeys, listOfEntries in output; 
#int, principal, strEnum, dnParam, dateTime, intEnum, otpTokenKey, dnorurl, everything above dnsrecord_show/1 in option; 
#principal, dnsNameParam, password in arg
'''

#code to parse through api.txt to create ipa api
#assume makeReq() exists

from backend import Write, Command, IPA
import re

fd = open('API.txt', 'r')
lines = fd.readlines()
commands = []
args = {}
options = []
output = []

an = 0
opn = 0
outn = 0
n_args = 1
n_options = 1
n_output = 1

c = None
count = 0

w = open('methods.py', 'w')
w.write('from backend import Param, Command, IPA\n')
w.close()
c = Command('',par='')

for line in lines:
	line = line.strip()
	if line.startswith('command:'):
		if count!=0:
			f = Write('methods.py', c, comName)
			f.write_rest(f, c, comName)
		line = re.sub(r'^command: ', '', line)
		commands.append(line)
		comName = line.replace('/1', '')
		c = Command(comName)
		count+=1
		#print comName

	if line.startswith('args'):
		line = line.replace('args: ', '')
		(na, nop, nott) = line.split(',')
		n_args = int(na)
		n_options = int(nop)
		n_output = int(nott)
		Command.args(c, n_args, n_options, n_output)

	if line.startswith('arg:'):
		line = line.replace('arg: ', '')
		args = line.split(',')
		line = line.replace('<', '')
		line = line.replace('>', '')
		res = line.split('(', 2)
		par = 'Command(' + res[1]
		n = res[1].split(',')
		Command.arg(c, n[0], par)
		an+=1

	if line.startswith('option:'):
		line = line.replace('option: ', '')
		if line.startswith('DNParam'):
			orl = line
			index = line.index('(')
			line = line[index+1:len(line)]
			if 'ipapython' in line:
				line = line[:len(line)]
			n = line.split(',',3)
			par = 'Command(' + line
			if 'ipapython' in orl:
				Command.DNParam(c, n[0], n)
			else:
				Command.option(c, n[0], par=par)

		else:
			options = line.split(',')
			line = line.replace('<', '\'')
			line = line.replace('>', '\'')
			res = line.split('(', 2)
			n = res[1].split(',')
			par = 'Command(' + res[1]
			Command.option(c, n[0], par)
		opn+=1

	if line.startswith('output:'):
		line = line.replace('output: ', '')
		output = line.split(',')
		if 'type' in line:
			line = line.replace('<type ', '')
			line = line.replace('<', '')
			line = line.replace('>', '')
		res = line.split('(', 2)
		par = 'Command(' + res[1]
		n = res[1].split(',')
		Command.output(c, n[0], par)
		outn+=1
	if outn==n_output:
		fd.close()

'''
def hostgroup_add_member(cn, **kwargs):
	opt_all = kwargs['all']
	opt_host = kwargs['host']
	opt_hostgroup = kwargs['hostgroup']
	opt_no_members = kwargs['no_members']
	opt_raw = kwargs['raw']
	opt_version = kwargs['version']
	json_dict = {
				'id':0,
				'method': 'hostgroup_add_member/1',
				'params': [
							[cn],
							{
							'host': [opt_host]
							'version': opt_version
							}
						]
				}
	response = makeReq(json_dict)
	return response

-------Template-------------------------------
def <command>(<arg1>, <arg2>, .... **kwargs):
	opt_name1 = kwargs['opt_name1']
	opt_name2 = kwargs['opt_name2']
	...
	json_dict = {
				'id':0,
				'method': '<command>',
				'params': [
							[
							arg1,
							arg2,
							...
							],
							{
							'opt_name1': opt_name1
							'opt_name2': opt_name2
							...
							}
						]
				}
	response = makeReq(json_dict)
	return response
'''