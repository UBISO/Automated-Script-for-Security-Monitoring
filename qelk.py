from elasticsearch import Elasticsearch
import numpy as np
import math as m
from datetime import datetime,timedelta
from collections import defaultdict
import getopt,sys
import yaml
import ldap
import smtplib
from email.mime.text import MIMEText
import re
import csv

#This program searches the elasticsearch database and flags malicious logins.
#Minimum input attributes required to run elasticsearch are the number of hours to search and the config file. Alternatively help can be called without giving any other attributes.

#The end result is displayed to the user in the console and is mailed to the email address given in the "mailto" tag in the "smtp" tag in the config file.

#Method to show the different ways the user can run the program
def help():
	print("")
	print("HELP")
	print("The following command line flags can be added to the program")
	print("1. -h : for calling Help")
	print("2. -D : For each malicious user output, the raw IP records get dumped to a file called iprec.txt")
	print("3. -c : Lets the user define the config file for search in ldap system")
	print("4. -H : Lets the user define the last number of hours from which the records are to be retrieved")
	print("5. -u : Lets the user define the user UBID from which the records are to be retrieved")
	print("")

#Method to calculate the distance between 2 lattitude,longitude sets. Called from ELK() method.
def dcalc(lon1,lat1,lon2,lat2):
	R = 6371
	dlat = np.radians(lat2-lat1)
	dlon = np.radians(lon2-lon1)
	a = m.sin(dlat/2)*m.sin(dlat/2) + m.cos(np.radians(lat1))*m.cos(np.radians(lat2))*m.sin(dlon/2)*m.sin(dlon/2)
	c = 2*m.atan2(m.sqrt(a),m.sqrt(1-a))
	d = R*c*0.62137
	return d

#Method to flag users that are above the tuning velocity threshold passed in the config file. Called from ELK() Method.
def tthres(usern,dst,td,origin,destination,srcip,dstip):
	mph = dyaml['tuning']['mph']
	totaltime = float((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6)
	if(dst/mph > float(totaltime/3600)):
		userlist[usern].append([usern,origin,destination,round(dst,1),round(totaltime,1),srcip,dstip])
		if (fdebug):
			writer.writerow([str(round(totaltime,1)),str(usern),str(srcip),str(origin),str(dstip),str(destination)])


#Method to query elasticsearch and retreive the login information and check for malicious logins. Called from Main().
def ELK():
	es = Elasticsearch()
	global userlist
	userlist = defaultdict(list)

	gtime = str(datetime.now() - timedelta(hours=dhrs))
	ltime = str(datetime.now())

	if(inuser == "0"):
		rs = es.search(index="radius-*",scroll = '2m',body = {"query": {"bool": {"must": [{"range": {"RADIUS.Acct-Timestamp": {"gte":gtime, "lte":ltime}}}]}}},sort = 'RADIUS.Acct-Username:desc',size=10000)
	else:
		rs = es.search(index="radius-*",scroll = '2m',body = {"query": {"bool": {"must": [{"match": {"RADIUS.Acct-Username": inuser}},{"range": {"RADIUS.Acct-Timestamp": {"gte":gtime, "lte":ltime}}}]}}},sort = 'RADIUS.Acct-Username:desc',size=10000)

	v = []
	sid = rs['_scroll_id']
	scroll_size = rs['hits']['total']
	print("Total number of hits is " + str(scroll_size))
	if(scroll_size == 0):
		print("Search returned no records")
		sys.exit()
	while(scroll_size > 0):
		v += rs['hits']['hits']
		rs = es.scroll(scroll_id = sid, scroll = '2m')
		sid = rs['_scroll_id']
		scroll_size = len(rs['hits']['hits'])


	#v = res.get('hits').get('hits')

	for i in range(len(v)-1):
		for j in range(i+1, len(v)):
			try:
				if(v[i].get('_source').get('RADIUS.Acct-Username') == v[j].get('_source').get('RADIUS.Acct-Username')):
					if(v[i].get('_source').get('RADIUS.Acct-NAS-Port-Type') == "Virtual"):
						location1 = [v[i].get('_source').get('Incoming').get('location')[0],v[i].get('_source').get('Incoming').get('location')[1]]
						location2 = [v[j].get('_source').get('Incoming').get('location')[0],v[j].get('_source').get('Incoming').get('location')[1]]
						orig = v[i].get('_source').get('Incoming').get('country_name') + "//"  + v[i].get('_source').get('Incoming').get('region_name') + "//"  + v[i].get('_source').get('Incoming').get('city_name')
						origip = v[i].get('_source').get('Incoming').get('ip')
						dest = v[j].get('_source').get('Incoming').get('country_name') + "//" + v[j].get('_source').get('Incoming').get('region_name') + "//" + v[j].get('_source').get('Incoming').get('city_name')
						destip = v[j].get('_source').get('Incoming').get('ip')
					else:
						location1 = [v[i].get('_source').get('geoip').get('location')[0],v[i].get('_source').get('geoip').get('location')[1]]
						location2 = [v[j].get('_source').get('geoip').get('location')[0],v[j].get('_source').get('geoip').get('location')[1]]
						orig = v[i].get('_source').get('geoip').get('country_name') + "//" + v[i].get('_source').get('geoip').get('region_name') + "//" + v[i].get('_source').get('geoip').get('city_name')
						origip = v[i].get('_source').get('geoip').get('ip')
						dest = v[j].get('_source').get('geoip').get('country_name') + "//" + v[j].get('_source').get('geoip').get('region_name') + "//" + v[j].get('_source').get('geoip').get('city_name')
						destip = v[j].get('_source').get('geoip').get('ip')

					dist = dcalc(location1[0],location1[1],location2[0],location2[1])

					try:
						fdt1 = '.'.join(v[i].get('_source').get('RADIUS.Acct-Timestamp').split('.')[:-1])
						if not fdt1:
							fdt1 = '-'.join(v[i].get('_source').get('RADIUS.Acct-Timestamp').split('-')[:-1])
						if not fdt1:
							fdt1 = v[i].get('_source').get('RADIUS.Acct-Timestamp')

						fdt2 = '.'.join(v[j].get('_source').get('RADIUS.Acct-Timestamp').split('.')[:-1])
						if not fdt2:
							fdt2 = '-'.join(v[j].get('_source').get('RADIUS.Acct-Timestamp').split('-')[:-1])
						if not fdt2:
							fdt2 = v[j].get('_source').get('RADIUS.Acct-Timestamp')

						dt1 = datetime.strptime(fdt1, '%Y-%m-%d %H:%M:%S')
						dt2 = datetime.strptime(fdt2, '%Y-%m-%d %H:%M:%S')
						dt = abs(dt1-dt2)
						tthres(v[i].get('_source').get('RADIUS.Acct-Username'),dist,dt,orig,dest,origip,destip)
					except ValueError:
						print("Bad Data Exception " + fdt1)
						print("Bad Data Exception " + fdt2)
						pass

			#For handling empty login data sets.
			except AttributeError as e:
				pass
			except TypeError as e:
				pass


	#Code to handle ldap searches
	l = ldap.initialize(dyaml['ldap']['server'])
	basedn = dyaml['ldap']['base']
	searchScope = ldap.SCOPE_SUBTREE

	me = dyaml['smtp']['mailfrom']
	you = dyaml['smtp']['mailto']

	erme = dyaml['output']['errorsfrom']
	eryou = dyaml['output']['errorsto']


	for user in userlist:		
		searchFilter = "(&(uid="+ user + "))"
		try:
			ldap_result_id = l.search(basedn, searchScope, searchFilter)
			result_set = []
			while 1:
				result_type, result_data = l.result(ldap_result_id, 0)
				if (result_data == []):
					break
				else:
					if result_type == ldap.RES_SEARCH_ENTRY:
						result_set.append(result_data)
			umsg.append("\n------------------------------------------------------\n")
			rs = str(result_set)
			rsol = rs.split(",")
			rsol = [re.sub('[^A-Za-z0-9:=@. ]', '', x) for x in rsol]
			for ele in rsol:
				umsg.append(ele + "\n")
			umsg.append("\n------------------------------------------------------\n")
	

		except ldap.LDAPError, e:
			rrm = str(e)

		umsg.append("\n------------------------------------------------------\n")
		umsg.append("Origin\t" + "IP\t" + "Destination\t" + "IP\t" + "Distance(Miles)\t" + "Time(Secs)\t" + "Velocity(mph)\n")
		for ctr in range(len(userlist[user])):
			umsg.append(str(userlist[user][ctr][1]) + "\t")
			umsg.append(str(userlist[user][ctr][5]) + "\t")
			umsg.append(str(userlist[user][ctr][2]) + "\t")
			umsg.append(str(userlist[user][ctr][6]) + "\t")
			umsg.append(str(userlist[user][ctr][3]) + "\t")
			umsg.append(str(userlist[user][ctr][4]) + "\t")
			try:
				umsg.append(str(round(userlist[user][ctr][3]/(userlist[user][ctr][4]/3600),1)) + "\n")
			except ZeroDivisionError:
				umsg.append("Velocity undefined as time is zero\n")
				
				umsg.append("\n------------------------------------------------------\n")

			
	l.unbind_s() 	
	#Code to send mail to the required email addresses given in the config file

	sumsg = ''.join(umsg)
	
	if not umsg:
		emsg = MIMEText("Number of records processed is " + str(i) + " Time is " + str(datetime.now())  + " Collection is "+ sumsg)
	else:
		emsg = MIMEText(sumsg)
	
	emsg['Subject'] = 'Suspicious Login Alert'
	emsg['From'] = me
	emsg['To'] = you
	
	try:
		s = smtplib.SMTP('localhost')
		if not umsg:
	                print("No malicious logins were found")
        	        sys.exit()

		s.sendmail(me, [you], emsg.as_string())
		if 'rrm' in locals():
			errm = MIMEText(rrm)
			errm['Subject'] = 'Error in ldap search'
			errm['From'] = erme
			errm['To'] = eryou
			s.sendmail(erme,eryou, errm.as_string())
			print('LDAP Error, Error details sent to error mail')
		s.quit()

	except Exception as error:
		print(error)

	print(sumsg)

#Main function
def main():
	global dhrs
	global fdebug
	global inuser
	global fl
	global writer
	global dyaml
	global umsg

	fdebug = False
	inuser = "0"
	umsg = []

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hDc:fu:iH:t")
	except Exception as err:
		print(err)
		sys.exit(2)

	if not opts:
		print("Incorrect Format, please enter the right format")
		sys.exit()

	for o, a in opts:
		if o == "-h":
			help()
		elif o == "-D":
			fdebug = True
			fl = open("iprec.csv","wb")
			writer = csv.writer(fl, delimiter=',', quotechar='|', quoting=csv.QUOTE_NONE)
			writer.writerow(['time','username','sourceip','source location','destip','dest location'])
		elif o == "-c":
			with open(a, 'r') as stream:
					try:
						dyaml = yaml.load(stream)
					except yaml.YAMLError as exc:
						print(exc)
		elif o == "-u":
			inuser = a
		elif o == "-H":
			dhrs = int(a)
		else:
			print("Incorrect Format, please enter the right format")
		
	#Elasticsearch runs only when atleast the number of hours to be searched and the config file is provided.
	if('dyaml' in globals() and 'dhrs' in globals()):	
		ELK()
	else:
		print("Please give the config file for the ldap search and/or the number of hours to be searched")
		HELP()


	if fdebug:
		fl.close()	

if __name__ == '__main__':
	main()

