import requests
import urllib3
import urllib
import getopt
import sys
from requests_kerberos import HTTPKerberosAuth
from lxml import etree
from typing import Text


# this is to ignore the ssl insecure warning as we are passing in 'verify=false'
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
headers = {'Content-type': 'application/json'}

url = 'https://hsdes-api.intel.com/rest/query/MetaData'

# common_sql_mapping = {
#     "greater than": ">",
#     "greater than or equal to": ">=",
#     "less than": "<",
#     "less than or equal to": "<=",
#     "equal": "=",
#
# }

dps_sql_mapping = {
    "`central_firmware.bug`": "`calc_bug`",
    "`central_firmware.feature`": "`calc_feature`",
    "`central_firmware.test_case_definition`": "`calc_tcd`",
    "`central_firmware.test_case`": "`calc_tc`",
    "`central_firmware.test_result`": "`calc_tr`",
    "`central_firmware.integration_step_event`": "`calc_ise`",
    "`central_firmware.milestone`": "`test_cycle`",
    "`id`": "`hsd_id`",
    "contains": "like",
    "does not contain": "not like",
    "greater than or equal to": ">=",
    "less than or equal to": "<=",
    "greater than": ">",
    "less than": "<",
    "equal": "=",
}


def query(hsd_id):
    try:
        'https://hsdes-api.intel.com/rest/query/MetaData?id=1508334611&fields=query.query_xml%2Chsd_id'
        query_params = urllib.parse.urlencode({'id': hsd_id, 'fields': ','.join(['query.query_xml'])})
        endpoint = '?'
        endpoint += query_params
        url_hsd = url + endpoint
        response = requests.get(url_hsd, verify=False, auth=HTTPKerberosAuth(), headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return response.json()['message']
    except Exception as e:
        raise Exception(f"HSD[ {hsd_id} ]: {e}")

def with_xpath(xml_data:Text,xpath_expr:str,namespaces:dict=None)->list:
    if isinstance(xml_data, str):
        xml_data = xml_data.encode("utf-8")
    try:
        xml = etree.XML(xml_data)
        if namespaces and isinstance(namespaces,dict):
            list_result = xml.xpath(xpath_expr,namespaces=namespaces)
        else:
            list_result = xml.xpath(xpath_expr)
        return list_result
    except Exception as e:
        raise Exception(f"error：{e}")

def update_field(node, value, model):
    if node in ['CriteriaField', 'DisplayField'] \
            and model == 'dps':
        value = ['`{}`'.format(v.split('.')[-1])
                 if '.' in v else '`{}`'.format(v) for v in value]
    elif node in ['FieldOperator'] \
            and model == 'hsdes':
        value = ['{}'.format(v.replace(' ', '_'))
                 if ' ' in v and v not in ['not in'] else v for v in value]
    elif node in ['FieldValue']:
        value = ['({})'.format(v) for v in value]
    return value

def convert_to_sql(hsd_id=None, model=None):
    if not hsd_id or not model:
        return
    result = query(hsd_id)
    xml_data = result['data'][0].get('query.query_xml')
    xpath_mapping = {
        "WhereClause" : "Operand",
        "Subject" : "Value",
        "Criteria" : "Name",
        "CriteriaField" : "Value",
        "FieldOperator" : "Value",
        "FieldValue" : "Value",
        "DisplayField": "Fullname",
    }

    xml_xpath_value = {}
    namespaces = {'x': 'https://hsdes.intel.com/schemas/2012/Query'}
    for node, attr in xpath_mapping.items():
        value = with_xpath(xml_data, '//x:{node}/@{attr}'.
                           format(node=node, attr=attr), namespaces)
        xml_xpath_value[node] = update_field(node, value, model)
    print(xml_xpath_value)

    if xml_xpath_value['WhereClause'] == ['MATCH ALL']:
        where_clause = ' AND '.join(xml_xpath_value['Criteria'])
    elif xml_xpath_value['WhereClause'] == ['MATCH ANY']:
        where_clause = ' OR '.join(xml_xpath_value['Criteria'])
    elif xml_xpath_value['WhereClause'] == ['CUSTOM']:
        where_clause = with_xpath(xml_data, '//x:WhereClause/@Expression', namespaces)[0]
    else:
        return

    for t in zip(xml_xpath_value['Criteria'], xml_xpath_value['CriteriaField'],
                 xml_xpath_value['FieldOperator'], xml_xpath_value['FieldValue']):
        t_li = list(t)
        where_clause = where_clause.replace(t_li.pop(0), ' '.join(t_li), 1)
        print(where_clause)

    sql = None
    if model == 'dps':
        sql = """
            SELECT {fields} FROM `{subject}` WHERE {where_clause};
        """
        for k, v in dps_sql_mapping.items():
            sql = sql.format(fields=','.join(xml_xpath_value['DisplayField']),
                             subject=xml_xpath_value['Subject'][0],
                             where_clause=where_clause).replace(k, v)
        import re
        like_letters = re.findall('like [\(\']+(.*?)[\)\']+', sql)
        for letters in like_letters:
            print(letters)
            sql = sql.replace(letters, '%{}%'.format(letters))
    elif model == 'hsdes':
        sql = """
            SELECT {fields} WHERE tenant ={tenant} AND subject ={subject} AND {where_clause}
        """
        sql = sql.format(tenant=xml_xpath_value['Subject'][0].split('.')[0],
                         subject=xml_xpath_value['Subject'][0].split('.')[1],
                         where_clause=where_clause,
                         fields=','.join(xml_xpath_value['DisplayField']))

    print(sql.lstrip())

def _usage():
    usage = ("""
    Usage: Convert hsdes query to sql. 
    -h,--help Display help.
    -q,--query query hsd id.
    -m,--model Convert hsdes query to sql. There are two models: dps and hsdes.

    Examples:
        python main.py --query hsd_id --model dps

    """)
    return usage

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hq:m:", ["help", "query=", "model="])
    except getopt.GetoptError as err:
        print(err)
        sys.stderr.write(_usage())
        sys.exit(3)

    kwargs = {}
    for o, a in opts:
        if o in ('-h', '--help'):
            sys.stdout.write(_usage())
            sys.exit(0)
        elif o in ('-q', '--query'):
            kwargs['hsd_id'] = a
        elif o in ('-m', '--model'):
            kwargs['model'] = a
    convert_to_sql(**kwargs)


if __name__ == '__main__':
    main()
