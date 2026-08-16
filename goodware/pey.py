import re
import pefile 
import pandas as pd
import sys
#exefile = sys.argv[1]
#exefile = "MessageBox.exe"
def strings(filename):
	strings =[]
	try:
		pe= pefile.PE(filename)
		entirefiledata = pe.get_memory_mapped_image()
		text_filter = re.compile(b'[a-zA-Z0-9\s\.,!@#\$%\^&\*\(\)\-_\+=\[\]\{\};:\'"<>\?\/\\|~`]{4,}')
		for match in text_filter.finditer(entirefiledata):
			cleantext = match.group().decode('utf-8',errors='ignore')
			#print(cleantext)
			strings.append(cleantext)
		#if strings:
			#print("Successfully Added")
		#else:
			#print("Error While adding")
			 df3 = pd.DataFrame(strings,columns=["strings"])
			 print(df3)
			 return df3
	except Exception as e:
		print(f"Could not read the file: {e}")
		return pd.DataFrame()

def sectioner(filename):
	sections=[]
	for section in pe.sections:
		name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
		#print(f"Name : {name:<8}")
		VirtualAddress = hex(section.VirtualAddress)
		#print(f"VirtualAddress : {VirtualAddress}")
		size = section.SizeOfRawData
		#print(f"Raw Data Size: {size}")
		sections.append((name, VirtualAddress,size))
	#if sections:
	#	print("Successfull Added these Values in the section list")
	#else:
	#	print("Adding Error")
		df2 = pd.DataFrame(sections,columns=["Name","VirtualAddres","Size"])
		print(df2)
		return df2

def dller(filename):
	pe.parse_data_directories()
	importtables =[]
	dllnames = []
	if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dllname = entry.dll.decode('utf-8',errors='ignore')
			dllnames.append(dllname)
			df = pd.DataFrame(dllnames,columns=["DLLNAME"]
			print(df)
			return df
			#print(f"DLL NAME: {dllname}")

def importtabler(filename):
	if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):		
			for imp in entry.imports:
				if imp.name:
					func_name = imp.name.decode('utf-8',errors='ignore')
					importtables.append(func_name)
				else:
			#		print(f"Ordinal : {imp.ordinal}")
					importtables.append(imp.ordinal)
			df4= pd.DataFrame(importtables,columns=["Import Tables"])
			print(df4)
			return df4
	else:
		print("No Import Tables Found")
	#if importtables and dllnames:
	#	print("Successfully Added values to the import and dll tables")
	#else:
	#	print("Adding Error")

	
#parser(exefile)
