
from enum import Enum
import pandas as pd
import json
import glob
import os


class EnterpriseAPT29Eval():
	def __init__(self, filename):
		self._vendor = filename.split('/', 2)[2]
		self._vendor = self._vendor.split('.', 1)[0]
		with open(filename, 'r') as infile:
		    data=infile.read()

		self._obj = json.loads(data)['Techniques']
		self._df = pd.json_normalize(self._obj,'Steps', ['TechniqueId','TechniqueName', 'Tactics'])
		self._steps = None
		self._dfir = None
		self._mssp = None
		self._visibility = None
		self._correlated = None


	# sort and reindex dataframe by substep
	def sortSubSteps(self, cleanup=False):
		ver = self._df['SubStep'].str.split('.', expand=True)
		self._df['Major'] = ver[0].astype(int)
		self._df['Alpha'] = ver[1]
		self._df['Minor'] = ver[2].astype(int)
		self._df.sort_values(by=['Major','Alpha','Minor'], inplace=True)
		self._df.reset_index(drop=True, inplace=True)

		if cleanup:
			self._df.drop(columns=['Major', 'Alpha', 'Minor'], inplace=True)


	# flatten Tactics json, throwing away id's since not sequential anyway
	def flattenTactics(self, inplace=False):
		self._df['Tactics' if inplace else 'Tactic'] = self._df['Tactics'].apply(lambda x: x[0]['TacticName'] if len(x)==1 else x[0]['TacticName'] + ', ' + x[1]['TacticName'])


	# row level operations when flattening detections
	def _flattenDetections(self, detections, confchange=False):
		ret, mods, mssp = 'None', [], False
		dt = Enum('DetectionTypes', 'None Telemetry General Tactic Technique')

		for detection in detections:
			# check if we're allowing conf change and there is one
			if not confchange:
				ischange = False
				for modifier in detection['Modifiers']:
					if modifier.startswith('Configuration Change'):
						ischange = True
				if ischange:
					continue

			if detection['DetectionType'] == 'N/A':
				ret = detection['DetectionType']
				mods = detection['Modifiers']
				break

			if detection['DetectionType'] == 'MSSP':
				mssp = True
			elif dt[ret].value < dt[detection['DetectionType']].value:
				ret = detection['DetectionType']
				mods = detection['Modifiers']

		return pd.Series([ret, sorted(mods), mssp])


	def flattenDetections(self, inplace=False, confchange=False):
		detections = self._df['Detections'].apply(lambda x: self._flattenDetections(x, confchange))
		self._df['Detections' if inplace else 'Detection'] = detections[0]
		self._df['Modifiers'] = detections[1]
		self._df['MSSP'] = detections[2]


	def get_steps(self):
			
		if self._steps == None:
			self.flattenDetections(confchange=True)
			removed = pd.value_counts(self._df['Detection'].values)['N/A']
			self._steps = len(self._df.index) - removed
		return self._steps

	steps = property(get_steps)

	# This attempts to calculate the max visibility the product enables
	# when configured to see/detect everything as may be adventagous for
	# a digital forensics professional performing an incident response.
	def score_dfir(self):
		if self._steps == None:
			self.get_steps()
		if self._dfir == None:
			misses = pd.value_counts(self._df['Detection'].values)['None']
			self._dfir = self._steps - misses

	def get_dfir(self):
		if self._dfir == None:
			self.score_dfir()
		return self._dfir

	dfir = property(get_dfir)
	

	# This is a straight count of the number of MSSP detections reported
	# by MITRE during the evaluation. This scoring was done under the
	# DFIR configuration during the eval and must be compared to that.
	def score_mssp(self):
		if self._dfir == None:
			self.score_dfir()
		if self._mssp == None:
			if True in self._df['MSSP'].values:
				self._mssp = pd.value_counts(self._df['MSSP'].values)[True]
			else:
				self._mssp = 0

	def get_mssp(self):
		if self._mssp == None:
			self.score_mssp()
		return self._mssp

	mssp = property(get_mssp)


	def score_detections(self):
		if self._visibility == None:
			self.flattenDetections(confchange=False)
			misses = pd.value_counts(self._df['Detection'].values)['None']
			self._visibility = self._steps - misses
		if self._correlated == None:
			self._correlated = 0
			for index, row in self._df.iterrows():
				if 'Correlated' in row['Modifiers']:
					self._correlated += 1

	def get_visibility(self):
		if self._visibility == None:
			self.score_detections()
		return self._visibility

	visibility = property(get_visibility)


	def get_correlated(self):
		if self._correlated == None:
			self.score_detections()
		return self._correlated

	correlated = property(get_correlated)

	def get_vendor(self):
		return self._vendor

	vendor = property(get_vendor)


	def get_dataframe(self):
		return self._df

	df = property(get_dataframe)


def readout(results):
	print(f'{results.vendor}\n---------------------------')
	if results.mssp > 0:
		print(f'The MSSP service was able to detect {results.mssp} of the {results.dfir} events the product was able')
		print(f'to detect under a dfir configuration, for an efficacy of {(results.mssp * 100)/results.dfir :.2f}%')
	else:
		print(f'The vendor doesn\'t appear to have been leveraging an MSSP service. It should')
		print(f'still be noted that a dfir configuration identified {results.dfir} events.')

	print(f'\nThe product provided visibility out of the box for {results.visibility} of {results.steps} steps, for an')
	print(f'efficacy of {(results.visibility * 100)/results.steps :.2f}%')

	print(f'\nThe product was able to correlate {results.correlated} of the {results.visibility} events it had visibility into')
	print(f'out of the box, for an efficacy of {(results.correlated * 100)/results.visibility :.2f}%\n')


def write_xlsx(dfs, columns=['SubStep', 'Procedure', 'Tactic', 'TechniqueId', 'TechniqueName', 'Detection', 'Modifiers', 'MSSP']):
	writer = pd.ExcelWriter(f'apt29eval.xlsx', engine='xlsxwriter')
	for vendor in dfs.keys():
		dfs[vendor].flattenTactics()
		dfs[vendor].sortSubSteps(cleanup=True)
		dfs[vendor].df.to_excel(writer, sheet_name=vendor, index=False, columns=columns)
	writer.save()

if __name__ == '__main__':
	results = {}

	for infile in sorted(glob.glob(os.path.join('./data/', '*json'))):
		obj = EnterpriseAPT29Eval(infile)
		readout(obj)
		results.update({obj.vendor: obj})

	write_xlsx(results)


