#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ***********************************
# URL shortener running a Flask stack
# Created by Leon Sandøy for Conmodo
# ***********************************
#

## IMPORT BLOCK ##

# built-ins
import os
import sys
import urlparse
import requests
import string
import json

# third party
import psycopg2
from flask import Flask, render_template, request, redirect, url_for, abort

# user defined
from secrets import WOT_API_KEY, POSTGRES_PASS, DB_TABLE


## FUNCTION BLOCK ##

def connect_to_pg(dbname, user, password, host = 'localhost'):
	'''
	Logs into a PostgreSQL database
	and returns a connection object.

	Raises a ValueError if the login fails.
	'''
	try:
		connect = psycopg2.connect("dbname={0} user={1}\
                       				host={2} password={3}".format(
                       				dbname, user, host, password))
	except Exception as e:
		raise ValueError('Unable to connect to PostgreSQL database:', e)

	# cursor to operate database
	return connect

def get_domain(url, keep_schema=False):
	'''
	Finds the domain for a provided url.

	get_domain('short.beardfist.com')            -> 'short.beardfist.com'
	get_domain('http://www.beardfist.com/stuff') -> 'www.beardfist.com'
	get_domain('telegraph.co.uk/news')           -> 'telegraph.co.uk'
	'''

	parsed = urlparse.urlparse(url)

	domain = ''

	if keep_schema and parsed.scheme:
		domain += parsed.scheme + '://'

	domain += parsed.netloc

	return domain

def get_url_string(url):
	'''
	Gets the variable string part at the 
	end of the shortened URLs

	get_url_string('short.beardfist.com/abD12') -> 'abD12'

	'''
	parsed = urlparse.urlparse(url)

	# slicing off the leading '/'
	return parsed.path[1:]

def validate_short_url(url):
	'''
	Figures out whether or not the provided url 
	is a short_url created by this page.

	Returns True or False
	'''
	parsed = urlparse.urlparse(url)

	domain = get_domain(request.url)

	if(domain in parsed.netloc
	   and parsed.path and len(parsed.path)>1):

		return True

	return False

def validate_schema(url):
	'''
	Checks if the url has either http or https schema.

	If it has a valid http or https schema, it returns the url unaltered.
	If it doesn't have a schema, it prepends 'http://' and returns the url.
	If it has a different schema than http or https, the function raises a ValueError.

	This is to prevent sketchy schemas like data:// from being allowed.
	'''

	# determine which schema the url has
	schema = ''

	if '://' in url:
		schema = url[:url.find('://')]
	else:
		for char in url:
			# if the first punctuation character is a colon
			if char in string.punctuation:
				if char == ':':
					schema = url[:url.find(':')]
				break

	# return a working url or raise ValueError
	if schema in ['http', 'https']:
		return url
	elif schema == '':
		return 'http://' + url
	else:
		raise UserWarning('Illegal schema <b>{0}</b> detected in URL. Only <i>http and https</i> are permitted.'.format(schema))

def validate_url(url):
	'''
	Check to see if the url actually resolves.
	
	Returns the status_code if it's able to resolve it.
	If not, raises a UserWarning.

	This is to prevent junk data in our databases,
	and should also help prevent sketchy stuff like SQL injections.
	'''

	# try to connect to connect to the url
	try:
		request = requests.get(url)
	
	# generic catch because requests can raise 
	# a surprising number of  different errors.
	except Exception as e:
		raise UserWarning('Could not resolve <b>{0}</b>. Make sure the URL is valid.'.format(url))

	# return the status code
	return str(request.status_code) + ': ' + request.reason

def safe_check(url):
	'''
	Uses the Web of Trust API to check if 
	a url is potentially dangerous.

	Returns True if the website can be trusted.
	Otherwise, raises a UserWarning with an explanation.

	We're doing this to try to prevent people from
	using this service to scam others.
	'''

	# WOT doesn't deal well with long URLS, so let's just feed it the domain
	url = get_domain(url)

	request = requests.get('http://api.mywot.com/0.4/public_link_json2?hosts={0}/&callback=process&key={1}'.format(url, WOT_API_KEY))

	print(WOT_API_KEY)

	# strips away excess process() wrapper
	json_data = request.text[8:-1]

	# load the data with the json library
	try:
		request_json = json.loads(json_data) # May raise ValueError
	except ValueError as e:
		raise UserWarning("Critical JSON failure - Probably an expired WOT API key.")

	try:
		categories = request_json[next(iter(request_json))]['categories'] # may raise KeyError
		categories = [unwanted_WOT_categories[int(i)] for i in categories.keys()] # may raise KeyError

		# build error message
		error_message = 'We don\'t trust this page. This page may contain {0}.'.format(', '.join(categories).lower())
		raise UserWarning(error_message)

	except (KeyError, StopIteration):
		return True # Either WOT has no data, or the page is catagorically safe.

def next_short_string(prev_string=None, protected=False):
	'''
	This function generates a short string
	and returns it to the user.
	
	If a previous string is provided,
	it returns the next in the series.
	
	If a list of protected strings is provided,
	it will recursively generate new strings until 
	it finds a string that is not in that list.

	Allowed characters are a-z, A-Z and 0-9 (in that order)

	next_short_string('a')      -> 'b'
	next_short_string('abz')    -> 'abA'
	next_short_string('9')      -> 'aa'
	next_short_string('aBCf99') -> 'aCDgaa'
	next_short_string('9999')   -> 'aaaaa'
	'''

	def increment_symbol(letter):
		'''
		This helper function increments a symbol.

		increment_symbol('a') -> 'b'
		increment_symbol('z') -> 'A'
		increment_symbol('9') -> 'a'
		'''
		return allowed_characters[(allowed_characters.find(letter) + 1) % maxchar_limit]

	# if no prev_string was provided, we'll just start at 'a'
	if not prev_string:
		return 'a'

	# make the string a list so it'll be mutable
	new_string = list(prev_string)

	# iterate through the list backwards
	for num, symbol in reversed(list(enumerate(prev_string))):

		# always increment the last symbol
		if num + 1 == len(prev_string):
			new_string[num] = increment_symbol(symbol)

			# if that was the only symbol and it turned into an 'a', we gotta add another 'a' to the end.
			if num == 0 and new_string[num] == 'a':
				new_string.append('a')

		# if the previous symbol was incremented to 'a', keep incrementing
		elif new_string[num+1] == 'a':
			new_string[num] = increment_symbol(symbol)

			# if the first symbol just turned into an 'a', we have to add another 'a' to the end
			if num == 0 and new_string[num] == 'a':
				new_string.append('a')

		# if the previous symbol didn't turn into 'a', we don't need to keep going.
		else:
			break

	# put it back together
	new_string = ''.join(new_string)

	# if the string is one of the protected urls, start over.
	if protected and new_string in protected:
		new_string = next_short_string(new_string, protected) # yay, recursion!

	return new_string

def remove_non_ascii(s): 
	'''
	Removes non ascii characters
	from a string and returns
	the string without them.
	'''
	return "".join(i for i in s if ord(i) < 128)


## INIT BLOCK ##

# instanciate the Flask app
app = Flask(__name__)

# connecting to the postgres database
pg = connect_to_pg('short_url', 'postgres', 'Otvaaoe1809!')
cursor = pg.cursor()

# allowed short_string characters
allowed_characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
maxchar_limit = len(allowed_characters)

# stuff we don't want to be associated with
unwanted_WOT_categories = {101:'Malware or viruses', 103:'Phishing attempts', 104:'Scams', 
			   			   105:'Potentially illegal elements', 203:'Suspicious elements', 
			   			   204:'Hate, discrimination', 205:'Spam', 206:'Potentially unwanted programs'}

# protected url paths
protected_paths = ['reverse']

# this fixes some annoying unicode stuff
reload(sys)
sys.setdefaultencoding("utf-8")


## MAIN WEB BLOCK ##

@app.route('/', methods=['GET', 'POST'])
def main_page():
	'''
	This renders the main page found at root ('/').

	The decorator tells Flask that it should run this
	function whenever someone navigates to '/', and 
	that both GET and POST methods are permitted.

	This function then validates a url POSTed to it,
	and then checks if we already shortened it.
	
	If it's already in our database, it returns
	the existing record.
	
	If not, it creates a new record and returns that.
	'''

	# init
	url_is_safe     = False
	error 	  	    = False
	short_url 	    = ''
	long_url  	    = ''
	long_url_domain = ''
	

	# get the input from POST
	if request.method == 'POST':
		long_url = request.form.get('long_url')

	# validate long_url
	if long_url:
		try:

			# strip the url for leading and trailing whitespace
			long_url = long_url.strip()

			# remove non-ascii characters
			long_url = remove_non_ascii(long_url)

			# confirm that the schema is http or https
			long_url = validate_schema(long_url)  # may raise UserWarning
			
			# confirm that the url is valid and can be resolved
			url_status = validate_url(long_url)   # may raise ConnectionError

			if '404' in url_status:
				raise UserWarning('The domain <b>{0}</b> exists, but this specific URL gives a 404 error.'.format(get_domain(long_url)))

			# confirm that it doesn't contain malicious content
			url_is_safe  = safe_check(long_url)   # may raise UserWarning

			# confirm that the long_url isn't already a short.beardfist.com url
			if(request.url in long_url 
			and request.url != long_url):
				raise UserWarning('You cannot simplify a URL that\'s already been simplified.')

		except UserWarning as e:
			error = str(e)
			long_url = ''
			url_is_safe = False


	# url has been validated
	if url_is_safe:

		try:
			# first let's check if we've already shortened this URL
			cursor.execute("SELECT short_url FROM {0} WHERE long_url = '{1}';".format(DB_TABLE, long_url))
			short_url = cursor.fetchone()[0]
		
		except:
			# which string was used in the latest entry
			cursor.execute('SELECT short_url FROM {0} WHERE id=(select max(id) from {0})'.format(DB_TABLE))
			last_used_string = cursor.fetchone()[0]

			# generate the next string in the series
			short_url = next_short_string(last_used_string, protected_paths)
			
			# add it to the database
			cursor.execute("""INSERT INTO {0} (SHORT_URL, LONG_URL, HITS) 
						   VALUES ('{1}', '{2}', 0);""".format(DB_TABLE, short_url, long_url))
			pg.commit()
		
		# now prepend the domain itself
		short_url = request.url + short_url

		# set long_url_domain
		long_url_domain = get_domain(long_url)
		

	# display the page
	return render_template('index.html', short_url=short_url, long_url=long_url, long_url_domain=long_url_domain, error=error)

@app.route('/reverse', methods=['GET', 'POST'])
def reverse_page():
	'''
	This renders the reverse page found at '/reverse'.

	This function validates a shortened url POSTed to it,
	and then checks if it exists in the database.
	
	If it does, it returns a table with records about the entry.
	 _________________________________________________________
	| Short URL | Long URL 	 	   		| Created	   | Hits |
	|___________|_______________________|______________|______|
	| 	'aGd'	| www.beardfist.com		| 23.01.2017   | 241  |
	|___________|_______________________|______________|______|              											  |
	 
	If it is not found, returns an error message.
	'''

	# init
	valid_short_url  = False
	error 	  	     = False
	hits 			 = False
	created 		 = False
	short_url 	     = ''
	long_url  	     = ''
	url_string 		 = ''


	# get the input from POST
	if request.method == 'POST':
		short_url = request.form.get('short_url')

	# validate short_url
	if short_url:
		try:

			# strip the url for leading and trailing whitespace
			short_url = short_url.strip()

			# confirm that the schema is http or https
			short_url = validate_schema(short_url)  # may raise UserWarning

			# confirm that this is a short_url created by this app
			valid_short_url = validate_short_url(short_url)
			if not valid_short_url:
				raise UserWarning('Invalid short URL. We can only reverse URLs created by us.')

		except UserWarning as e:
			error = str(e)


	# url validated for reverse lookup
	if valid_short_url:

		#get the string itself
		url_string = get_url_string(short_url)

		try:
			# let's see if it exists in our database
			cursor.execute("SELECT * FROM {0} WHERE short_url = '{1}';".format(DB_TABLE, url_string))
			row = cursor.fetchone()
			
			# save the data so we can send it to the page.
			hits 	  = row[4]
			long_url  = row[2]
			created   = row[3].strftime("%d.%m.%Y")
			
		
		except:
			# it doesn't exist. return an error message.
			error = 'The short URL has valid syntax, but was not found in our database.'
			

	# display the page
	return render_template('reverse.html', short_url=short_url, long_url=long_url, error=error, hits=hits, created=created)

@app.route('/<short_url>')
def destination_redirect(short_url):
	'''
	This redirects the user to the long URL that our
	short URLs are related to in the database.

	It then increments the 'hits' property by 1.

	If it cannot find the short URL in the database, 
	it returns status code 404 to the browser.
	'''

	# Tries to fetch the long_url based on short_url. Prone to various exceptions.
	try:		
		cursor.execute("SELECT long_url FROM {0} WHERE short_url = '{1}';".format(DB_TABLE, short_url))
		long_url = cursor.fetchone()[0]
	except Exception:
		long_url = False		

	# Increments hits by one and then redirects the user
	if long_url:		
		cursor.execute("UPDATE {0} SET hits = hits + 1 WHERE short_url = '{1}';".format(DB_TABLE, short_url))
		pg.commit()
		return redirect(long_url)
	else:
		return abort(404)

# main function
if __name__ == '__main__':
    app.run()
