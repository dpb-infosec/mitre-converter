import json
from jsonpath_ng import jsonpath, parse
from jinja2 import Environment, FileSystemLoader

file_loader = FileSystemLoader('templates')
env = Environment(loader=file_loader)
mitre_objs = []
template = env.get_template('layer.jinja2')


def color(x):
    return {
        'high': '#00358a',
        'medium': '#6ea6ff',
        'low': '#b6d1fc'
    }[x]


with open('./mappings.json', 'r') as f:
    ibm_mapping = json.load(f)


jsonpath_expr = parse('$..mapping..techniques.*')

for technique in jsonpath_expr.find(ibm_mapping):
    if technique.value['enabled']:
        mitre_objs.append({
            "techniqueID": technique.value['id'],
            "color": color(technique.value['confidence'])
        })

with open('./layer.json', 'w+') as f:
    f.write(template.render(techniques=mitre_objs))
