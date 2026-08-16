from pathlib import Path
from pey import parser
import pandas as pd
import sqlite3

conn = sqlite3.connect("yara_goodware.db")
cursor = conn.cursor()

dirpath = Path("malwares/malware")

files = []

for item in dirpath.iterdir():
    df,df2,df3,df4 = parser(str(item))
    files.append((df,df2,df3,df4))

total = len(files)

dlls = []
sections = []
imports = []
strings = []

for df,df2,df3,df4 in files:
    dlls.append(df.drop_duplicates())
    sections.append(df2.drop_duplicates())
    strings.append(df3.drop_duplicates())
    imports.append(df4.drop_duplicates())

alldlls = pd.concat(dlls)['DLLNAME'].value_counts()
allsections = pd.concat(sections).value_counts(subset=['Name','VirtualAddres','Size'])
allstrings = pd.concat(strings)['strings'].value_counts()
allimports = pd.concat(imports)['Import Tables'].value_counts()

hifreq = []
scores = []
titles_for_scores=[]

cursor.execute("""
    SELECT COUNT(DISTINCT source_file) FROM goodware_features
    """)

total_goodware = cursor.fetchone()[0]

#print("Total Goodware Samples:",total_goodware)

for i in range(len(alldlls)):
    if alldlls.iloc[i] >= 4:
        hifreq.append((alldlls.index[i],alldlls.iloc[i]))
    else:
        continue

for feature,family_count in hifreq:
    cursor.execute("""
        SELECT COUNT(DISTINCT source_file)
        FROM goodware_features
        WHERE feature_type = ?
        AND feature = ?
    """,("dll",feature))

    goodware_count = cursor.fetchone()[0]
    rarity_score = 1/(1+goodware_count)
    family_freq=family_count / total

    scores.append(
        ("dll",feature,float(family_freq),int(goodware_count),float(rarity_score))
    )
"""
    print(
        f"{feature} | "
        f"Family: {family_count} | "
        f"Goodware: {goodware_count} | "
        f"Rarity={rarity_score:.4f}"
    )"""

hifreq = []

for i in range(len(allsections)):
    if allsections.iloc[i] >= 4:
        hifreq.append((allsections.index[i],allsections.iloc[i]))
    else:
        continue

for feature,family_count in hifreq:

    section_name = feature[0]

    cursor.execute("""
        SELECT COUNT(DISTINCT source_file)
        FROM goodware_features
        WHERE feature_type = ?
        AND feature = ?
    """,("section",section_name))

    goodware_count = cursor.fetchone()[0]
    rarity_score = 1/(1+goodware_count)
    family_freq=family_count / total

    scores.append(
        ("section",feature,float(family_freq),int(goodware_count),float(rarity_score))
    )

    """print(
        f"{section_name} | "
        f"Family: {family_count} | "
        f"Goodware: {goodware_count} | "
        f"Rarity={rarity_score:.4f}"
    )"""

hifreq = []

for i in range(len(allstrings)):
    if allstrings.iloc[i] >= 4:
        hifreq.append((allstrings.index[i],allstrings.iloc[i]))
    else:
        continue

for feature,family_count in hifreq:
    cursor.execute("""
        SELECT COUNT(DISTINCT source_file)
        FROM goodware_features
        WHERE feature_type = ?
        AND feature = ?
    """,("string",feature))

    goodware_count = cursor.fetchone()[0]
    rarity_score = 1/(1+goodware_count)
    family_freq=family_count / total

    scores.append(
        ("string",feature,float(family_freq),int(goodware_count),float(rarity_score))
    )

    """print(
        f"{feature} | "
        f"Family: {family_count} | "
        f"Goodware: {goodware_count} | "
        f"Rarity={rarity_score:.4f}"
    )"""

hifreq = []

for i in range(len(allimports)):
    if allimports.iloc[i] >= 4:
        hifreq.append((allimports.index[i],allimports.iloc[i]))
    else:
        continue

for feature,family_count in hifreq:
    cursor.execute("""
        SELECT COUNT(DISTINCT source_file)
        FROM goodware_features
        WHERE feature_type = ?
        AND feature = ?
    """,("import",feature))

    goodware_count = cursor.fetchone()[0]
    rarity_score = 1/(1+goodware_count)
    family_freq=family_count / total

    scores.append(
        ("import",feature,float(family_freq),int(goodware_count),float(rarity_score))
    )

    """print(
        f"{feature} | "
        f"Family: {family_count} | "
        f"Goodware: {goodware_count} | "
        f"Rarity={rarity_score:.4f}"
    )"""

#print("=" * 20)
#print("SCORES")
#print(scores)
#rint("=" * 20)

penalty_multiplier = 3
discriminative_scores = []

for feature_type,feature,family_freq,goodware_count,rarity_score in scores:

    goodware_freq = goodware_count / total_goodware

    discriminative_score = family_freq - goodware_freq * penalty_multiplier

    discriminative_scores.append(
        (
            feature_type,
            feature,
            float(family_freq),
            int(goodware_count),
            float(goodware_freq),
            float(rarity_score),
            float(discriminative_score)
        )
    )

    """print(
        f"{feature} | "
        f"Family Frequency: {family_freq:.4f} | "
        f"Goodware: {goodware_count} | "
        f"Goodware Frequency: {goodware_freq:.4f} | "
        f"Rarity={rarity_score:.4f} | "
        f"Discriminative Score: {discriminative_score:.4f}"
    )"""

#print("=" * 20)
#print("DISCRIMINATIVE SCORES")
#print(discriminative_scores)
#print("=" * 20)

Discriminative_desc = sorted(discriminative_scores,key=lambda x:x[-1],reverse=True)
filtereddata = []
topn = 10
for x in Discriminative_desc :
	if x[0] == "string" or x[0] == "dll":
		filtereddata.append(x)
topfeature = filtereddata[:topn]
foryara =[]
def feature_for_rule_gen():
    for feature_type,y,_,_,_,_,x in topfeature:
    	foryara.append((feature_type,y,x))
    return foryara
    #print(topfeature)
conn.close()
if __name__ == "__main__":
    feature_for_rule_gen()



