# global imports
import sys
import time

import requests
from fake_useragent import UserAgent

# local imports
from getmyancestors.classes.translation import translations


import gi
gi.require_version("Gtk", "3.0")		# GUI toolkit
gi.require_version("WebKit2", "4.0")	# Web content engine
from gi.repository import Gtk, WebKit2

class miniBrowser():

    def __init__(self, *args, **kwargs):
        self.code=''
        # create window
        self.main_window = Gtk.Window(title = "Connection…")
        self.main_window.connect('destroy', Gtk.main_quit)	# connect the "destroy" trigger to Gtk.main_quit procedure
        self.main_window.set_default_size(800, 800)		# set window size

        # Create view for webpage
        self.web_view = WebKit2.WebView()				# initialize webview
        self.web_view.load_uri(args[0])	# default homepage
        self.web_view.connect('notify::title', self.change_title)	# trigger: title change
        self.web_view.connect('notify::uri', self.change_uri)	# trigger: webpage is loading
        self.scrolled_window = Gtk.ScrolledWindow()		# scrolling window widget
        self.scrolled_window.add(self.web_view)

        # Add everything and initialize
        self.vbox_container = Gtk.VBox()		# vertical box container
        self.vbox_container.pack_start(self.scrolled_window, True, True, 0)
        
        self.main_window.add(self.vbox_container)
        self.main_window.show_all()
        Gtk.main()

    def change_title(self, widget, frame):
        self.main_window.set_title(self.web_view.get_title())

    def change_uri(self, widget, frame):
        uri = self.web_view.get_uri()
        if uri[0:10]=='https://mi':
          poscode=uri.find('code=')
          if poscode>0 :
            self.code= uri[poscode+5:]
            print("change_url:code="+self.code)
          self.main_window.close()


class Session(requests.Session):
    """Create a FamilySearch session
    :param username and password: valid FamilySearch credentials
    :param verbose: True to active verbose mode
    :param logfile: a file object or similar
    :param timeout: time before retry a request
    """

    def __init__(self, username, password, verbose=False, logfile=False, timeout=60):
        super().__init__()
        self.username = username
        self.password = password
        self.verbose = verbose
        self.logfile = logfile
        self.timeout = timeout
        self.fid = self.lang = self.display_name = None
        self.counter = 0
        self.headers = {"User-Agent": UserAgent().firefox}
        self.login()

    @property
    def logged(self):
        return bool(self.cookies.get("fssessionid") or hasattr(self,'access_token'))

    def write_log(self, text):
        """write text in the log file"""
        log = "[%s]: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
        if self.verbose:
            sys.stderr.write(log)
        if self.logfile:
            self.logfile.write(log)

    def login(self) :
        # voir https://github.com/misbach/fs-auth/blob/master/index_raw.html
        appKey = 'a02j000000KTRjpAAH'
        redirect = 'https://misbach.github.io/fs-auth/index_raw.html'
        url = 'https://ident.familysearch.org/cis-web/oauth2/v3/authorization?response_type=code&scope=openid profile email qualifies_for_affiliate_account country&client_id='+appKey+'&redirect_uri='+redirect+'&username='+ self.username
        # ouvrir une fenêtre de navigation
        print("url= "+url)
        main = miniBrowser(url)
        print("code="+main.code)
        headers= {"Accept": "application/json"}
        headers.update ( {"Content-Type": "application/x-www-form-urlencoded"})
        data = {
                   "grant_type": 'authorization_code',
                   "client_id": appKey,
                   "code": main.code,
                   "redirect_uri": redirect,
                 }
        url = 'https://ident.familysearch.org/cis-web/oauth2/v3/token'
        json = self.post_url(url,data,headers)
        if json :
          if json.get('access_token') :
            self.access_token = json['access_token']
            print("FamilySearch-ĵetono akirita")
            self.set_current()
            return True
          else:
            print(" échec de connexion")
            print("        , r.text="+r.text)
            return False
        else:
          print(" échec de connexion")
          return False

    def login_old(self):
        """retrieve FamilySearch session ID
        (https://familysearch.org/developers/docs/guides/oauth2)
        """
        while True:
            try:
                url = "https://www.familysearch.org/auth/familysearch/login"
                self.write_log("Downloading: " + url)
                self.get(url, headers=self.headers)
                xsrf = self.cookies["XSRF-TOKEN"]
                url = "https://ident.familysearch.org/login"
                self.write_log("Downloading: " + url)
                res = self.post(
                    url,
                    data={
                        "_csrf": xsrf,
                        "username": self.username,
                        "password": self.password,
                    },
                    headers=self.headers,
                )
                try:
                    data = res.json()
                except ValueError:
                    self.write_log("Invalid auth request")
                    continue
                if "loginError" in data:
                    self.write_log(data["loginError"])
                    return
                if "redirectUrl" not in data:
                    self.write_log(res.text)
                    continue

                url = data["redirectUrl"]
                self.write_log("Downloading: " + url)
                res = self.get(url, headers=self.headers)
                res.raise_for_status()
            except requests.exceptions.ReadTimeout:
                self.write_log("Read timed out")
                continue
            except requests.exceptions.ConnectionError:
                self.write_log("Connection aborted")
                time.sleep(self.timeout)
                continue
            except requests.exceptions.HTTPError:
                self.write_log("HTTPError")
                time.sleep(self.timeout)
                continue
            except KeyError:
                self.write_log("KeyError")
                time.sleep(self.timeout)
                continue
            except ValueError:
                self.write_log("ValueError")
                time.sleep(self.timeout)
                continue
            if self.logged:
                self.set_current()
                break

    def get_url(self, url, headers=None):
        """retrieve JSON structure from a FamilySearch URL"""
        self.counter += 1
        if headers is None:
            headers = {"Accept": "application/x-gedcomx-v1+json"}
        headers.update(self.headers)
        if hasattr(self,'access_token') :
          headers ["Authorization"] = 'Bearer '+self.access_token
        if url[0:4] != 'http' :
          url="https://api.familysearch.org" + url
        nbtry = 0
        #import pdb; pdb.set_trace()
        while True:
            try:
                if nbtry > 3 :
                  return None
                nbtry = nbtry + 1
                self.write_log("Downloading: " + url)
                r = self.get(
                    url,
                    timeout=self.timeout,
                    headers=headers,
                )
            except requests.exceptions.ReadTimeout:
                self.write_log("Read timed out")
                continue
            except requests.exceptions.ConnectionError:
                self.write_log("Connection aborted")
                time.sleep(self.timeout)
                continue
            self.write_log("Status code: %s" % r.status_code)
            if r.status_code == 204:
                return None
            if r.status_code in {404, 405, 410, 500}:
                self.write_log("WARNING: " + url)
                return None
            if r.status_code == 401:
                self.login()
                return None
            try:
                r.raise_for_status()
            except requests.exceptions.HTTPError:
                self.write_log("HTTPError")
                if r.status_code == 403:
                    if (
                        "message" in r.json()["errors"][0]
                        and r.json()["errors"][0]["message"]
                        == "Unable to get ordinances."
                    ):
                        self.write_log(
                            "Unable to get ordinances. "
                            "Try with an LDS account or without option -c."
                        )
                        return "error"
                    self.write_log(
                        "WARNING: code 403 from %s %s"
                        % (url, r.json()["errors"][0]["message"] or "")
                    )
                    return None
                time.sleep(self.timeout)
                continue
            try:
                return r.json()
            except Exception as e:
                self.write_log("WARNING: corrupted file from %s, error: %s" % (url, e))
                return None

    def post_url(self, url,data, headers=None):
        """retrieve JSON structure from a FamilySearch URL"""
        self.counter += 1
        if headers is None:
            headers = {"Accept": "application/x-gedcomx-v1+json"}
        headers.update(self.headers)
        if hasattr(self,'access_token') :
          headers ["Authorization"] = 'Bearer '+self.access_token
        if url[0:4] != 'http' :
          url="https://api.familysearch.org" + url
        nbtry = 1
        while True:
            try:
                if nbtry > 3 :
                  return None
                nbtry = nbtry + 1
                self.write_log("Downloading: " + url)
                r = self.post(
                    url,
                    timeout=self.timeout,
                    headers=headers,
                    data=data,
                    allow_redirects=False
                )
            except requests.exceptions.ReadTimeout:
                self.write_log("Read timed out")
                continue
            except requests.exceptions.ConnectionError:
                self.write_log("Connection aborted")
                time.sleep(self.timeout)
                continue
            self.write_log("Status code: %s" % r.status_code)
            if r.status_code == 204:
                return None
            if r.status_code in {404, 405, 410, 500}:
                self.write_log("WARNING: " + url)
                return None
            if r.status_code == 401:
                self.login()
                return None
            try:
                r.raise_for_status()
            except requests.exceptions.HTTPError:
                self.write_log("HTTPError")
                if r.status_code == 403:
                    if (
                        "message" in r.json()["errors"][0]
                        and r.json()["errors"][0]["message"]
                        == "Unable to get ordinances."
                    ):
                        self.write_log(
                            "Unable to get ordinances. "
                            "Try with an LDS account or without option -c."
                        )
                        return "error"
                    self.write_log(
                        "WARNING: code 403 from %s %s"
                        % (url, r.json()["errors"][0]["message"] or "")
                    )
                    return None
                time.sleep(self.timeout)
                continue
            try:
                return r.json()
            except Exception as e:
                self.write_log("WARNING: corrupted file from %s, error: %s" % (url, e))
                return None

    def set_current(self):
        """retrieve FamilySearch current user ID, name and language"""
        url = "/platform/users/current"
        data = self.get_url(url)
        if data:
            self.fid = data["users"][0]["personId"]
            self.lang = data["users"][0]["preferredLanguage"]
            self.display_name = data["users"][0]["displayName"]

    def _(self, string):
        """translate a string into user's language
        TODO replace translation file for gettext format
        """
        if string in translations and self.lang in translations[string]:
            return translations[string][self.lang]
        return string
