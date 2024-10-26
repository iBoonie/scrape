import sqlite3, requests, urllib, urllib3, json, time, re, warnings, asyncio, aiohttp

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from urllib.parse import urlparse
from aiohttp import ClientSession
from pathlib import Path

warnings.filterwarnings('ignore', category=MarkupResemblesLocatorWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_servers():
	f = open('servers.json')
	data = json.load(f)
	f.close()
	return data

def steamid_to_accountid(steamid: str):
	steamid_split = steamid.split(':')
	return int(steamid_split[2]) * 2 + int(steamid_split[1])

def build_search_regex(search_query: str):
	rx = '(' + re.escape(search_query) + ')'
	return re.compile(rx, re.IGNORECASE)

def get_hostname(url: str):
	url = urlparse(url)
	return url.hostname

def build_scrape_array():
	server_defaults = json_data['default']

	for server in json_data['servers']:
		url = urlparse(server['url'])

		for ban_string in server_defaults['search']:
			ban_string_encoded = urllib.parse.quote_plus(ban_string)

			info_dict = {
				'scrape': True,
				'url': f"{server['url']}{server_defaults['sourcebans']}{ban_string_encoded}&page=",
				'page': 1,
				'regex': build_search_regex(ban_string),
				'hostname': None,
				'id': server['server_id']
			}

			# If we are using an IP to bypass cloudflare, add the hostname so we can add it in a header later
			if (server.get('ip') != None):
				info_dict.update({
					'url': f"{url.scheme}://{server['ip']}{url.path}{server_defaults['sourcebans']}{ban_string_encoded}&page=",
					'hostname': url.hostname
				})

			if (server.get('sb_icon') != None):
				info_dict.update({
					'sb_icon': server['sb_icon']
				})

			scrape_data.append(info_dict)

		# Some sites use a custom ban string, add them here
		if (server.get('search') != None):
			for ban_string in server['search']:
				ban_string_encoded = urllib.parse.quote_plus(ban_string)

				info_dict = {
					'scrape': True,
					'url': f"{server['url']}{server_defaults['sourcebans']}{ban_string_encoded}&page=",
					'page': 1,
					'regex': build_search_regex(ban_string),
					'hostname': None,
					'id': server['server_id']
				}

				if (server.get('ip') != None):
					info_dict.update({
						'url': f"{url.scheme}://{server['ip']}{url.path}{server_defaults['sourcebans']}{ban_string_encoded}&page=",
						'hostname': url.hostname
					})

				if (server.get('sb_icon') != None):
					info_dict.update({
						'sb_icon': server['sb_icon']
					})

				scrape_data.append(info_dict)

def build_headers(hostname: str):
	headers = {
		"Cache-Control": "no-cache"
	}

	if (hostname != None):
		headers.update({
		    "Host": hostname
		})

	return headers

def has_blacklisted_string(string: str, blacklist: str):
	for match in blacklist:
		if match in string:
			return True
	return False

def process_page(index: int, response: str):
	global scrape_data, bans_added

	print(f"{scrape_data[index]['url']}{scrape_data[index]['page']}")

	soup = BeautifulSoup(response, 'html.parser')

	if (soup.body == None):
		scrape_data[index]['scrape'] = False
		print(f"{'': <12}No page body")
		return

	ban_is_tf = '!@*#@tf!!-+=@'

	# Make sure to only add TF2 bans
	# Check the MOD and append identifier
	for img in soup.body.find_all('img', alt='MOD'):
		mod = Path(img['src']).stem.lower()
		
		if (mod == 'tf' or mod == 'tf2' or mod == 'tf2_ico'):
			img.append(ban_is_tf)

		# Custom sourceban ban image, old sourcebans dont use game logo, or the logo is named different
		if (scrape_data[index].get('sb_icon') != None):
			if (mod == scrape_data[index]['sb_icon']):
				img.append(ban_is_tf)


	number_of_bans = 0
	steamid = None
	ban_reason = None
	is_tf = False
	bans_arr = []

	for stripped in soup.body.stripped_strings:
		# This was a TF2 ban
		if (stripped == ban_is_tf):
			is_tf = True
			continue

		if (re.match(regex_steamid, stripped)):
			steamid = steamid_to_accountid(stripped)
			ban_reason = None
			continue

		if (re.match(scrape_data[index]['regex'], stripped)):
			# Iterate here since we want to check total bans on page 
			# and dont care about bhop stuff or not
			number_of_bans += 1

			# Dont log Bhop bans from LilAC, it has false positives
			# Case sensitive, STAC is all lowercase
			blacklist = ["Bhop", "Bunny hop", "检测到连跳脚本"]
			if (has_blacklisted_string(stripped, blacklist)):
				print(f"{'': <12}Skipping: {stripped}")
				continue

			# Remove everything after the first period (with a space after it) to remove demo names
			ban_reason = stripped.partition('. ')[0]

		if (steamid != None and ban_reason != None):
			if (is_tf == True):
				bans_arr.append([scrape_data[index]['id'], steamid, ban_reason])

			steamid = None
			ban_reason = None
			is_tf = False

	print(f"{'': <12}Total Page Bans: {number_of_bans}")

	if (bans_arr):
		cur.executemany("INSERT OR IGNORE INTO bans (server_id, steamid, reason) VALUES (?, ?, ?)", bans_arr)
		con.commit()

		# If inserted rowcount isnt 0, try and process the next page
		if (cur.rowcount != 0):
			bans_added += cur.rowcount
			scrape_data[index]['page'] += 1
			print(f"{'': <12}Inserted {cur.rowcount} bans")
			return
			
	scrape_data[index]['scrape'] = False

async def fetch_html(index: int, session: ClientSession, **kwargs):
	global dead_hosts

	try:
		response = await session.request(method="GET", url=scrape_data[index]['url']+str(scrape_data[index]['page']), ssl=False, timeout=30, headers=build_headers(scrape_data[index]['hostname']), **kwargs)

		if (response.status == 200):
			process_page(index, await response.text())
		else:
			dead_hosts += 1
			scrape_data[index]['scrape'] = False
			print(f"{get_hostname(scrape_data[index]['url'])} response: {response.status}")
	except Exception as err:
		dead_hosts += 1
		scrape_data[index]['scrape'] = False
		print(f"{get_hostname(scrape_data[index]['url'])} Error: {err}")

async def make_requests(**kwargs) -> None:
	async with ClientSession() as session:
		tasks = []
		for index, item in enumerate(scrape_data):
			if (item['scrape'] == False):
				continue

			tasks.append(
				fetch_html(index=index, session=session, **kwargs)
			)
		
		# return_exceptions true so we can eat connection errors
		await asyncio.gather(*tasks, return_exceptions=True)

		for item in scrape_data:
			if (item['scrape'] == True):
				await make_requests()
				break

# -----------------------------
# ----------- ENTRY -----------
# -----------------------------

con = sqlite3.connect("communityBans.sq3")
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS bans (id INTEGER PRIMARY KEY, server_id TEXT, steamid TEXT, reason TEXT, UNIQUE(server_id, steamid))")

bans_added = dead_hosts = 0
start_time = time.time()
scrape_data = []
json_data = load_servers()
regex_steamid = re.compile('(STEAM_\d:\d:\d+)', re.IGNORECASE)

build_scrape_array()
asyncio.run(make_requests())
con.close()

print("---------------------")
print(f" Bans Added: {bans_added}")
print(f" Total Hosts: {len(json_data['servers'])}")
print(f" Dead URLs: {dead_hosts}/{len(scrape_data)}")
print(f" Scrape Time: {(time.time() - start_time):.2f}s")
# print("---------------------")
# input("Press Enter to continue...")
