#!/usr/bin/env python

from __future__ import print_function
import io, os, sys, re, json, base64, getpass, subprocess, shlex, signal, datetime
from lxml import etree
import requests
#import pdb     #pdb.set_trace()
#import webbrowser
#import mmap

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException

if sys.version_info >= (3,):
    from urllib.parse import urljoin
    text_type = str
    binary_type = bytes
else:
    from urlparse import urljoin
    text_type = unicode
    binary_type = str
    input = raw_input

to_b = lambda v: v if isinstance(v, binary_type) else v.encode('utf-8')
to_u = lambda v: v if isinstance(v, text_type) else v.decode('utf-8')

def log(s):
    print('[INFO] {0}'.format(s))

def dbg(d, h, *xs):
    if not d:
        return
    print('# {0}:'.format(h))
    for x in xs:
        print(x)
    print('---')

def err(s):
    print('err: {0}'.format(s))
    sys.exit(1)

def parse_xml(xml):
    try:
        xml = bytes(bytearray(xml, encoding='utf-8'))
        parser = etree.XMLParser(ns_clean=True, recover=True)
        return etree.fromstring(xml, parser)
    except:
        err('failed to parse xml')

def parse_html(html):
    try:
        parser = etree.HTMLParser()
        return etree.fromstring(html, parser)
    except:
        err('failed to parse html')

def parse_rjson(r):
    try:
        return r.json()
    except:
        err('failed to parse json')

def parse_form(html, current_url = None):
    xform = html.find('.//form')
    url = xform.attrib.get('action', '').strip()
    if not url.startswith('http') and current_url:
        url = urljoin(current_url, url)
    data = {}
    for xinput in html.findall('.//input'):
        k = xinput.attrib.get('name', '').strip()
        v = xinput.attrib.get('value', '').strip()
        if len(k) > 0 and len(v) > 0:
            data[k] = v
    return url, data

def load_conf(cf):
    conf = {}
    keys = ['vpn_url', 'username', 'webdriver', 'webdriver_dir']
    line_nr = 0
    with io.open(cf, 'r', encoding='utf-8') as fp:
        for rline in fp:
            line_nr += 1
            line = rline.strip()
            mx = re.match(r'^\s*([^=\s]+)\s*=\s*(.*?)\s*(?:#\s+.*)?\s*$', line)
            if mx:
                k, v = mx.group(1).lower(), mx.group(2)
                if k.startswith('#'):
                    continue
                for q in '"\'':
                    if re.match(r'^{0}.*{0}$'.format(q), v):
                        v = v[1:-1]
                conf[k] = v
                conf['{0}.line'.format(k)] = line_nr
    for k, v in os.environ.items():
        k = k.lower()
        if k.startswith('gp_'):
            k = k[3:]
            if len(k) == 0:
                continue
            conf[k] = v.strip()
    if len(conf.get('username', '').strip()) == 0:
        conf['username'] = input('username: ').strip()
    if len(conf.get('webdriver', '').strip()) == 0:
        cconf['webdriver'] = input('webdriver: ').strip()
    if len(conf.get('webdriver_dir', '').strip()) == 0:
        cconf['webdriver_dir'] = input('webdriver_dir: ').strip()
    for k in keys:
        if k not in conf:
            err('missing configuration key: {0}'.format(k))
        else:
            if len(conf[k].strip()) == 0:
                err('empty configuration key: {0}'.format(k))
    conf['debug'] = conf.get('debug', '').lower() in ['1', 'true']
    return conf

def mfa_priority(conf, ftype, fprovider):
    if ftype == 'token:software:totp':
        ftype = 'totp'
    if ftype not in ['totp', 'sms']:
        return 0
    mfa_order = conf.get('mfa_order', '')
    if ftype in mfa_order:
        priority = (10 - mfa_order.index(ftype)) * 100
    else:
        priority = 0
    value = conf.get('{0}.{1}'.format(ftype, fprovider))
    if ftype == 'sms':
        if not (value or '').lower() in ['1', 'true']:
            value = None
    line_nr = conf.get('{0}.{1}.line'.format(ftype, fprovider), 0)
    if value is None:
        priority += 0
    elif len(value) == 0:
        priority += (128 - line_nr)
    else:
        priority += (512 - line_nr)
    return priority

def get_redirect_url(conf, c, current_url = None):
    rx_base_url = re.search(r'var\s*baseUrl\s*=\s*\'([^\']+)\'', c)
    rx_from_uri = re.search(r'var\s*fromUri\s*=\s*\'([^\']+)\'', c)
    if not rx_from_uri:
        dbg(conf.get('debug'), 'not found', 'formUri')
        return None
    from_uri = to_b(rx_from_uri.group(1)).decode('unicode_escape').strip()
    if from_uri.startswith('http'):
        return from_uri
    if not rx_base_url:
        dbg(conf.get('debug'), 'not found', 'baseUri')
        if current_url:
            return urljoin(current_url, from_uri)
        return from_uri
    base_url = to_b(rx_base_url.group(1)).decode('unicode_escape').strip()
    return base_url + from_uri

def send_req(conf, s, name, url, data, **kwargs):
    dbg(conf.get('debug'), '{0}.request'.format(name), url)
    do_json = True if kwargs.get('json') else False
    headers = {}
    if do_json:
        data = json.dumps(data)
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'
    if kwargs.get('get'):
        r = s.get(url, headers=headers)
    else:
        r = s.post(url, data=data, headers=headers)
    hdump = '\n'.join([k + ': ' + v for k, v in sorted(r.headers.items())])
    rr = 'status: {0}\n\n{1}\n\n{2}'.format(r.status_code, hdump, r.text)
    if r.status_code != 200:
        err('okta {0} request failed. {0}'.format(rr))
    dbg(conf.get('debug'), '{0}.response'.format(name), rr)
    if do_json:
        return r.headers, parse_rjson(r)
    return r.headers, r.text

def paloalto_prelogin(conf, s):
    log('prelogin request')
    url = '{0}/global-protect/prelogin.esp'.format(conf.get('vpn_url'))
    #url = '{0}/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Linux'.format(conf.get('vpn_url'))
    h, c = send_req(conf, s, 'prelogin', url, {}, get=True)
    x = parse_xml(c)
    saml_req = x.find('.//saml-request')
    if saml_req is None:
        err('did not find saml request')
    if len(saml_req.text.strip()) == 0:
        err('empty saml request')
    try:
        saml_raw = base64.b64decode(saml_req.text)
    except:
        err('failed to decode saml request')
    dbg(conf.get('debug'), 'prelogin.decoded', saml_raw)
    saml_xml = parse_html(saml_raw)
    return saml_raw

def paloalto_getconfig(conf, s, saml_username, prelogin_cookie):
    log('getconfig request')
    url = '{0}/global-protect/getconfig.esp'.format(conf.get('vpn_url'))
    data = {
        'user': saml_username,
        'passwd': '',
        'inputStr': '',
        'clientVer': '4100',
        'clientos': 'Windows',
        'clientgpversion': '4.1.0.98',
        'computer': 'DESKTOP',
        'os-version': 'Microsoft Windows 10 Pro, 64-bit',
        # 'host-id': '00:11:22:33:44:55'
        'prelogin-cookie': prelogin_cookie,
        'ipv6-support': 'no'
    }
    h, c = send_req(conf, s, 'getconfig', url, data)
    x = parse_xml(c)
    xtmp = x.find('.//portal-userauthcookie')
    if xtmp is None:
        err('did not find portal-userauthcookie')
    portal_userauthcookie = xtmp.text
    if len(portal_userauthcookie) == 0:
        err('empty portal_userauthcookie')
    return portal_userauthcookie

def fun_prelogin_cookie(conf, s, saml_xml):
    rc = 0
    prelogin_cookie = ""
    stringToMatch = '"prelogin-cookie"'
    form_url, form_data = None, {}
    saml_username = conf.get('username')
    webdrivers = conf.get('webdriver')
    web_dir = os.path.expanduser(conf.get('webdriver_dir'))
    if not os.path.exists(web_dir):
        os.makedirs(web_dir)
    if os.path.isfile("{0}/chromedriverxx.log".format(web_dir)):
        os.remove("{0}/chromedriverxx.log".format(web_dir))
    if not os.path.exists(webdrivers):
        log('Configuration "webdriver" is incorrect, file "{0}" not exists'.format(webdrivers))
        sys.exit(1)
    options = Options()
    d = DesiredCapabilities.CHROME
    d['loggingPrefs'] = { 'performance':'ALL' }
    options.add_argument("--user-data-dir={0}".format(web_dir))
    options.add_argument("--window-size=666,666")
    options.add_argument("--app={0}".format(saml_xml))
    driver = webdriver.Chrome(executable_path=webdrivers, options=options,
                        service_args=["--verbose",
                        "--log-path={0}/chromedriverxx.log".format(web_dir)],
                        desired_capabilities=d)
    try:
        WebDriverWait(driver,180).until(EC.text_to_be_present_in_element((By.XPATH, '/html/body'), 'Login Successful!'))
    except TimeoutException:
        driver.quit()
        return saml_username, None
    prelogin_cookie = driver.page_source.split('<prelogin',)[1].split('>',1)[1].split('<',1)[0]
    driver.quit()
    if not prelogin_cookie:
        return saml_username, None
    return saml_username, prelogin_cookie

def main():
    if len(sys.argv) < 2:
        print('usage: {0} <conf>'.format(sys.argv[0]))
        sys.exit(1)
    conf = load_conf(sys.argv[1])

    #pdb.set_trace()
    s = requests.Session()
    s.headers['User-Agent'] = 'PAN GlobalProtect'
    saml_xml = paloalto_prelogin(conf, s).decode("utf-8")
    if conf['debug']:
        log('sessionToken: {0}'.format(saml_xml))
    saml_username, prelogin_cookie = fun_prelogin_cookie(conf, s, saml_xml)
    if not prelogin_cookie:
        sys.exit(1)
    if conf['debug']:
        log('saml-username: {0}'.format(saml_username))
        log('prelogin-cookie: {0}'.format(prelogin_cookie))
    userauthcookie = paloalto_getconfig(conf, s, saml_username, prelogin_cookie)
    if conf['debug']:
        log('portal-userauthcookie: {0}'.format(userauthcookie))

    #sudo openconnect --prot=gp --usergroup gateway:prelogin-cookie
    #   vpn.azimo.com -vvv --dump-http-traffic --timestamp
    #   -u pawel.szmuc@azimo.com 1>/tmp/open
    cmd = conf.get('openconnect_cmd') or 'openconnect'
    cmd += ' --protocol=gp -u \'{0}\''
    if conf['debug']:
        cmd += ' -vvv --dump-http-traffic --timestamp'
    else:
        cmd += ' -l'
    cmd += ' --script ./vpnc-script'
    cmd += ' --os=mac-intel'
    cmd += ' --usergroup portal:portal-userauthcookie'
    cmd += ' --passwd-on-stdin ' + conf.get('openconnect_args', '') + ' \'{1}\''
    cmd = cmd.format(conf.get('username'), conf.get('vpn_url'))

    gw = (conf.get('gateway') or '').strip()
    bugs = ''
    if conf.get('bug.nl', '').lower() in ['1', 'true']:
        bugs += '\\n'
    if conf.get('bug.username', '').lower() in ['1', 'true']:
        bugs += '{0}\\n'.format(username.replace('\\', '\\\\'))
    if len(gw) > 0:
        pcmd = 'printf \'' + bugs + '{0}\\n{1}\''.format(userauthcookie, gw)
    else:
        pcmd = 'printf \'' + bugs + '{0}\''.format(userauthcookie)
    print()
    if conf.get('execute', '').lower() in ['1', 'true']:
        web_dir = os.path.expanduser(conf.get('webdriver_dir'))
        logfile = open("{0}/openconnect.log".format(web_dir), "a", 1)
        logfile.write('!!! New VPN connection - {0}!!!\n'.format(datetime.datetime.now()))
        cmd = shlex.split(cmd)
        cmd = [os.path.expandvars(os.path.expanduser(x)) for x in cmd]
        pp = subprocess.Popen(shlex.split(pcmd), stdout=subprocess.PIPE)
        cp = subprocess.Popen(cmd, stdin=pp.stdout, stdout=logfile)
        pp.stdout.close()
        # Do not abort on SIGINT. openconnect will perform proper exit & cleanup
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cp.communicate()
        logfile.close()
    else:
        print('{0} | {1}'.format(pcmd, cmd))

if __name__ == '__main__':
    main()
