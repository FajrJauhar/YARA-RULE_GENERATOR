from pathlib import Path
from pey import parser
import pandas as pd
dirpath = Path("malwares/")
files =[]
for item in dirpath.iterdir():
	df,df2,df3,df4=parser(str(item))
	files.append((df,df2,df3,df4))

"""for i in files:
	df,df2,df3,df4= i
	dll = df['DLLNAME'].value_counts()
	print(dll)
	section = df2.value_counts(subset=['Name','VirtualAddres','Size'])
	print(section)
	string= df3['strings'].value_counts()
	print(string)
	importer = df4['Import Tables'].value_counts()
	print(importer)
"""
total = len(files)
dlls=[]
sections=[]
imports=[]
strings=[]
for df,df2,df3,df4 in files:
	dlls.append(df.drop_duplicates())
	sections.append(df2.drop_duplicates())
	strings.append(df3.drop_duplicates())
	imports.append(df4.drop_duplicates())
alldlls=pd.concat(dlls)['DLLNAME'].value_counts()
allsections = pd.concat(sections).value_counts(subset=['Name','VirtualAddres','Size'])
allstrings  = pd.concat(strings)['strings'].value_counts()
allimports  = pd.concat(imports)['Import Tables'].value_counts()


print(f"DLL Commonality Score (out of {total} samples are : {alldlls}")
print(f"Sections Commonality Score (out of {total} samples are : {allsections}")
print(f"Strings Commonality Score (out of {total} samples are : {allstrings}")
print(f"Imports Commonality Score (out of {total} samples are : {allimports}")




