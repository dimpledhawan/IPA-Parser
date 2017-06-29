import re
import requests
import json
import logging
import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ReadOnly(object):
	def __init__(self, name, **kwargs):
		self.info = {
			'name': '',
			'cli_name': '',
			'autofill': '',
			'alwaysask': '',
			'default': '',
			'option_group': '',
			'type': [],
			'values': '',
			'num_arg': '',
		}
		#print args
		if '?' in name:
			name = name.replace('?', '')
			self.info['num_arg'] = 'zo'
		if '*' in name:
			name = name.replace('*', '')
			self.info['num_arg'] = 'zm'
		if '+' in name:
			name = name.replace('+', '')
			self.info['num_arg'] = 'om'
		
		self.info['name'] = name
		self.info['name'].replace('/1', '')
			
		if 'cli_name' in kwargs:
			self.info['cli_name'] = kwargs['cli_name']
		else:
			self.info['cli_name'] = name
		if 'autofill' in kwargs:
			self.info['autofill'] = kwargs['autofill']
		if 'alwaysask' in kwargs:
			self.info['alwaysask'] = kwargs['alwaysask']
		if 'default' in kwargs:
			self.info['default'] = kwargs['default']
		if 'option_group' in kwargs:
			self.info['option_group'] = kwargs['option_group']
		if 'type' in kwargs:
			self.info['type'] = kwargs['type']
		if 'values' in kwargs:
			self.info['values'] = kwargs['values']
		if 'par' in kwargs:
			self.info['par'] = kwargs['par']
		self.a = 1
		self.op = 1
		self.out = 1

class Command(ReadOnly):
	def __init__(self, name, **kwargs):
		super(Command, self).__init__(name, **kwargs)
		self.com_dict = {}
		self.pname = ''
		self.n_args = 0
		self.n_options = 0
		self.n_output = 0

	def args(self, n_args, n_options, n_output):
		self.n_args = n_args
		self.n_options = n_options
		self.n_output = n_output
		for n in range(1,n_args+1):
			s = 'arg{}'.format(n)
			self.com_dict[s] = {}
		for n in range(1,n_options+1):
			s = 'option{}'.format(n)
			self.com_dict[s] = {}
		for n in range(1,n_output+1):
			s = 'output{}'.format(n)
			self.com_dict[s] = {}
			
	def arg(self, name, par):
		arg_dict = eval(par).info
		s = 'arg{}'.format(self.a)
		self.com_dict[s] = arg_dict
		self.a += 1
		
	def option(self, name, par):
		opt_dict = eval(par).info
		s = 'option{}'.format(self.op)
		self.com_dict[s] = opt_dict
		self.op += 1
		
	def output(self, name, par):
		out_dict = eval(par).info
		s = 'output{}'.format(self.out)
		self.com_dict[s] = out_dict
		self.out += 1
		
	def DNParam(c, name, n):
		if 'cn' in n[3]:
			index1 = n[3].find('cn')
			index2 = n[3].find(')')
			c.com_dict['default'] = n[3][index1:index2-1]
		if 'ou' in n[3]:
			index1 = n[3].find('ou')
			index2 = n[3].find(')')
			c.com_dict['default'] = n[3][index1:index2-1]
		sub = 'default'
		r = ''.join(s for s in n if sub.lower() in s.lower())
		n.remove(r)
		m = ','.join(map(str, n))
		par = 'Command(' + m + ')'
		Command.option(c, n[0], par)
		
class IPA(object):
	def __init__(self, server, sslverify=False):
		self.server = server
		self.sslverify = sslverify
		self.log = logging.getLogger(__name__)
		self.session = requests.Session()

	def login(self, user, password):
		rv = None
		ipaurl = 'https://{0}/ipa/session/login_password'.format(self.server)
		header = {'referer': ipaurl, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'text/plain'}
		login = {'user': user, 'password': password}
		rv = self.session.post(ipaurl, headers=header, data=login, verify=self.sslverify)
		if rv.status_code != 200:
			self.log.warning('Failed to log {0} in to {1}'.format(user,self.server))
			rv = None
		else:
			self.log.info('Successfully logged in as {0}'.format(user))
			self.login_user = user
		self.header = rv.headers
		return rv

	def makeReq(self, pdict):
		results = None
		ipaurl = 'https://{0}/ipa'.format(self.server)
		session_url = '{0}/session/json'.format(ipaurl)
		header ={'referer': ipaurl, 'Content-Type': 'application/json'}
		data = {'id': 0, 'method': pdict['method'], 'params': [pdict['item'], pdict['params']]}
		self.log.debug('Making {0} request to {1}'.format(pdict['method'], session_url))
		request = self.session.post(session_url, headers=header, data=json.dumps(data), verify=self.sslverify)
		results = request.json()
		return results

	def host_find(self, hostname=None, in_hg=None, sizelimit=40000):
		m = {'method': 'host_find', 'item': [hostname], 'params': {'all': True, 'in_hostgroup': in_hg, 'sizelimit': sizelimit}}
		results = self.makeReq(m)
		return results

class Write(object):
	def __init__(self, f, c, comName):
		self.fw = open(f, 'a')
	
	def write_rest(self, f, c, comName):
		self.fw.write('\ndef ' + comName + '(')
		for n in range(1,c.n_args):
			s = 'arg{}'.format(n)
			self.fw.write(c.com_dict[s]['name']+ ', ')
		if c.n_args != 0:
			s = 'arg{}'.format(c.n_args)
			self.fw.write("{}".format(c.com_dict[s]['name'])+', **kwargs):\n')
		for n in range(1,c.n_options+1):
			s = 'option{}'.format(n)
			self.fw.write('\topt_{}'.format(c.com_dict[s]['name'])+' = kwargs[{}{}{}]\n'.format("'", c.com_dict[s]['name'], "'"))
		self.fw.write("\n\tjson_dict = {")
		self.fw.write("\n\t\t'id':0,\n\t\t'method': '{}',\n".format(comName))
		self.fw.write("\t\t'params': [[")
		for n in range(1,c.n_args):
			s = 'arg{}'.format(n)
			self.fw.write("{}, ".format(c.com_dict[s]['name']))
		if c.n_args != 0:
			s = 'arg{}'.format(c.n_args)
			self.fw.write("{} ],".format(c.com_dict[s]['name']))
		self.fw.write("\n\t\t\t\t{ ")
		for n in range(1,c.n_options):
			s = 'option{}'.format(n)
			self.fw.write("\n\t\t\t\t'{}': opt_{}, ".format(c.com_dict[s]['name'], c.com_dict[s]['name']))
		s = 'option{}'.format(c.n_options)
		self.fw.write("\n\t\t\t\t'{}': opt_{}".format(c.com_dict[s]['name'], c.com_dict[s]['name']))
		self.fw.write('\n\t\t\t\t}\n\t\t\t]\n\t\t}')
		self.fw.write('\n\tresponse = makeReq(json_dict)\n\treturn response\n\n')