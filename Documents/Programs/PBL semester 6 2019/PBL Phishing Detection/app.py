from flask import Flask, render_template, request
import pickle
import inputScript
import numpy as np
import phishtank
import xml.etree.ElementTree as ET
import urllib2
import os
import requests
import whois
classifier = pickle.load(open('final_models/rf_final.pkl', 'rb'))
def percentageSafety(cp):
    positive=0
    negative=0
    for i in range(0,len(cp)):
	if(cp[i]==1):
	    positive=positive+1
	if(cp[i]==-1):
	    negative=negative+1	
    overall = len(cp)
    pos= (positive*100)/overall
    neg= (negative*100)/overall
    print("Safety meter:",pos)
    print("Suspicioun meter:",neg)
    return pos



def CheckIfURLPresentInPhishTank(url):
	"""
	Checks Phishtank database
	"""
	p = phishtank.PhishTank()
	result = p.check(url)
	if result.in_database:
		if result.valid:
			return 'Phish'
		else:
			return 'Safe'
	else:
		return 'Not in database'

def pagerank(url):
	"""
	Alexa page rank
	"""
	xmlresponse = urllib2.urlopen('http://data.alexa.com/data?cli=10&url='+url)
	html = xmlresponse.read()
	root = ET.fromstring(html)
	try:
		GlobalRank = (root[0][1].get('RANK'))
		NationRank = (root[0][3].get('RANK'))
		NationName = (root[0][3].get('NAME'))
	except:
		GlobalRank = "None"
		NationRank = "None"
		NationName = "None"
	return GlobalRank, NationRank, NationName
"""
def MoreDetails(url):
	#Website additional details
	AdditionalDetails = whois.whois(url).text
	return AdditionalDetails
"""

app = Flask(__name__)
@app.route('/send', methods=['GET', 'POST'])
def send():
    if(request.method == 'POST'):
        url = request.form['url']
	cp = inputScript.main(url)
	pos=percentageSafety(cp)
	try:
		if(requests.get(url).status_code == 200):
			URLStatus = 'Online'
		else:
			URLStatus = 'Offline'
	except:
		URLStatus="Unknown"		
	GlobalRank, NationRank, NationName = pagerank(url)
	checkprediction=np.reshape(cp, (1, -1))
	prediction = classifier.predict(checkprediction)
	if(prediction<0.1):
		PTResult = "Safe"
		pos=(pos+100)/2
	elif(prediction>0.6): 
		PTResult = "Phishing"
		try:
			""" Checking if model prediction is true or not """			
			p = phishtank.PhishTank()
			result = p.check(url)
			if result.in_database:
				if result.valid:
					PTResult = "Phishing"
				else:
					PTResult = "Safe"
			else:
				PTResult = "Safe"
		except:
			PTResult = "Phishing"
	else: 
		PTResult = "Suspicious"	
	return render_template('result.html',URL=url, STATUS=URLStatus, PHISHSTATUS=PTResult, PercentageOfSafety=pos, GLOBALRANK=GlobalRank, NATIONNAME=NationName, NATIONRANK=NationRank)
    return render_template('index.html')


if(__name__) == "__main__":
    app.run(debug=True)	

