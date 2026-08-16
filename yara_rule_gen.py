from dir import feature_for_rule_gen

a= feature_for_rule_gen()
for feature_type,feature , score in a:
	print(feature_type, feature, score)
def generate_rule_yara(rulename, features,filepath):
	rule_strings={}
	
	for i,(feature_type, feature,score) in enumerate(features):
		if feature_type == "string":
			rule_strings[f"$string_{i}"] = f'"{feature}"'
		elif feature_type == "dll":
			rule_strings[f"$dll_{i}"] = f'"{feature}"'
	string_block = ""
			
	for key ,value in rule_strings.items():
		string_block += f"        {key} = {value}\n"
	
	
	description="Dynamic Rule"
	condition= "any of them"
	ruletemplate = f"""rule {rulename}
 {{
	meta:
	    description = "{description}"
	    generated_by = "Python Dynamic Generator"
	strings:
 {string_block}
	condition:
	    {condition}
}}"""
	
	
	with open(filepath,'w',encoding = "utf-8") as f:
		f.write(ruletemplate)

generate_rule_yara("Dynamic_Yara_Rule_GEN",a,"dynamic_rule.yar")
