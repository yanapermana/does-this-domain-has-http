import nmap

def doesThisDomainHaveHTTP(domain):
	nm = nmap.PortScanner()
	nm.scan(domain, '80')
	if nm.all_hosts():
		host = nm.all_hosts()[0]
		if nm[host]['tcp'][80]['state'] == 'open':
			return 1
	return 0

with open('domains.lst') as f:
	for l in f:
		domain = l.rstrip()
		print domain, doesThisDomainHaveHTTP(domain)
		if doesThisDomainHaveHTTP(domain):
			with open('domainsHasHTTP.lst', 'a+') as g:
				g.write(domain)
				g.write('\r\n')
