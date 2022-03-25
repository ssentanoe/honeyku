#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017  Adel "0x4D31" Karimi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from flask import Flask, request, render_template, send_file, jsonify
import logging
from logging.handlers import TimedRotatingFileHandler
import sys
import os
import json
import time
import urllib.request
import urllib.error
import smtplib
import base64
from datetime import datetime

__author__ = 'Adel "0x4d31" Karimi'
__version__ = '0.1'

# Log to stdout
# On Heroku, anything written to stdout or stderr is captured into your logs.
# https://devcenter.heroku.com/articles/logging
logger = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
logger.addHandler(out_hdlr)
file_hdlr = TimedRotatingFileHandler("logs/honeyku.log", when="d", interval=1, backupCount=10)
logger.addHandler(file_hdlr)
logger.setLevel(logging.INFO)

app = Flask(__name__)

config = dict()
sorrirConfig = dict

@app.route('/', defaults={'path': ''}, methods=["GET","POST","PUT"])
@app.route('/<path:path>', methods=["GET","POST","PUT"])
def catch_all(path):
	# Honeytoken alerts
	if request.path != "/favicon.ico":

		request.data = consumeBody(request.data)

		# Prepare and send the custom HTTP response
		contype, body, http_status = generate_http_response(request, config)

		# Preparing the alert message
		alertMessage = alert_msg(request, config, http_status)

		# Honeypot event logs
		logger.info(json.dumps(alertMessage))

		# Customize the response using a template (in case you want to return a dynamic response, etc.)
		# You can comment the next 2 lines if you don't want to use this. /Just an example/
		if body == "custom.html":
			return (render_template(body, browser = request.user_agent.browser, ua = request.user_agent.string)), http_status

		if contype == "application/json":
			with open('templates/'+body) as f:
				d = json.load(f)
				return jsonify(d), http_status

		return (send_file(body, mimetype=contype) if "image" in contype else render_template(body)), http_status

	return "", 200

def load_config(configPath):
	""" Load the configuration from local file """
	with open(configPath) as config_file:
		conf = json.load(config_file)
		print(configPath + " config file loaded")

	return conf

def merge_config():
	connectionTechs = sorrirConfig["CommunicationConfiguration"]["connectionTechs"]
	for a in connectionTechs:
		if a["commOption"] == "REST":
			url = "/" + a["targetContainer"] + "/" + a["targetComponent"] + "/" + a["targetPort"]
			newEntry = {
				"trap-note": "Expected source: " + a["sourceContainer"] + "; Expected component: " + a["sourceComponent"],
				"trap-response": {
					"content-type": "application/json",
					"body": "empty.json"
				}
			}
			config["traps"][url] = newEntry

	#clean up sorrir config
	sorrirConfig.clear()

def generate_http_response(req, conf):
	""" Generate HTTP response """

	args = ["{}={}".format(key, value) for key, value in request.args.items()]
	path = req.path
	con_type = None
	body_path = None
	http_status = 200
	if path in conf['traps']:
		# Check if the token is defined and has a custom http response
		for token in args:
			if (token in conf['traps'][path]) and ("token-response" in conf['traps'][path][token]):
				con_type = conf['traps'][path][token]['token-response']['content-type']
				body_path = conf['traps'][path][token]['token-response']['body']
		# if the 'body_path' is still empty, use the trap/uri response (if there's any)
		if ("trap-response" in conf['traps'][path]) and body_path is None:
			con_type = conf['traps'][path]['trap-response']['content-type']
			body_path = conf['traps'][path]['trap-response']['body']
	# Load the default HTTP response if the 'body_path' is None
	if body_path is None:
		con_type = conf['default-http-response']['content-type']
		body_path = conf['default-http-response']['body']
		http_status = 404

	return con_type, body_path, http_status


def alert_msg(req, conf, http_status):
	""" Prepare alert message dictionary """

	# Message fields
	url_root = req.url_root
	full_path = req.full_path
	path = req.path
	data = req.data
	http_method = req.method
	useragent_str = req.user_agent.string
	browser = req.user_agent.browser
	browser_version = req.user_agent.version
	browser_lang = req.user_agent.language
	platform = req.user_agent.platform
	headers = "{}".format(req.headers)
	headersDict = {}
	for i in req.headers:
		headersDict[i[0]] = i[1]
	argsDict = {}
	for i in req.args:
		argsDict[i] = req.args[i]
	formDict = {}
	for i in req.form:
		formDict[i] = req.form[i]
	args = ["{}={}".format(key, value) for key, value in request.args.items()]
	# X-Forwarded-For: the originating IP address of the client connecting to the Heroku router
	if req.headers.getlist("X-Forwarded-For"):
		source_ip = req.headers.getlist("X-Forwarded-For")[0]
	else:
		source_ip = req.remote_addr

	# Search the config for the token note
	note = None
	if path in conf['traps']:
		# Check if the token is defined and has note
		for token in args:
			if (token in conf['traps'][path]) and ("token-note" in conf['traps'][path][token]):
				note = conf['traps'][path][token]['token-note']
		# If the 'note' is still empty, use the trap/uri note (if there's any)
		if ("trap-note" in conf['traps'][path]) and note is None:
			note = conf['traps'][path]['trap-note']

	#TODO: Threat Intel Lookup (Cymon v2)

	# Message dictionary
	msg = {
		"token_note": note if note else "None",
		"host": url_root,
		"path": full_path if full_path else "None",
		"http_method": http_method,
		"token": args[0] if args else "None", #Only the first arg
		"body": data if data else "None",
		"sourceip": source_ip,
		"user-agent": useragent_str,
		"browser": browser if browser else "None",
		"browser_version": browser_version if browser_version else "None",
		"browser_lang": browser_lang if browser_lang else "None",
		"platform": platform if platform else "None",
		"http-headers": headersDict,
		"timestamp": iso_8601_format(datetime.now()),
		"args": argsDict,
		"form": formDict,
		"http_response": http_status
		#"threat-intel": threat_intel
	}

	return msg

#https://stackoverflow.com/questions/34044820/python-iso-8601-date-format
def iso_8601_format(dt):
	"""YYYY-MM-DDThh:mm:ssTZD (1997-07-16T19:20:30-03:00)"""

	if dt is None:
		return ""

	fmt_datetime = dt.strftime('%Y-%m-%dT%H:%M:%S')
	tz = dt.utcoffset()
	if tz is None:
		fmt_timezone = "+00:00"
	else:
		fmt_timezone = str.format('{0:+06.2f}', float(tz.total_seconds() / 3600))

	return fmt_datetime + fmt_timezone

def consumeBody(body):
	try:
		a = json.loads(body)
		return a
	except:
		return body.decode("utf-8")

if __name__ == '__main__':
	
	#load config once
	configFound = False
	sorrirConfigFound = False
	try:
		config = load_config("config.json")
		configFound = True
	except:
		pass

	try:
		config = load_config("/config.json")
		configFound = True
	except:
		pass

	try:
		sorrirConfig = load_config("sorrir.json")
		sorrirConfigFound = True
	except:
		pass
	
	try:
		sorrirConfig = load_config("/sorrir.json")
		sorrirConfigFound = True
	except:
		pass
	
	#config loaded, run the app
	if configFound and sorrirConfigFound:
		merge_config()
		app.run(host='0.0.0.0', debug=False, use_reloader=True, port=11111)
