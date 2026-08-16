from pathlib import Path
from pey import parser
dirpath = Path("goodware/")
for item in dirpath.iterdir():
	string = parser(str(item))
	print(string)
