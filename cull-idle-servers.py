#!/usr/bin/env python3
"""script to monitor and cull idle single-user servers
Caveats:
last_activity is not updated with high frequency,
so cull timeout should be greater than the sum of:
- single-user websocket ping interval (default: 30s)
- JupyterHub.last_activity_interval (default: 5 minutes)
You can run this as a service managed by JupyterHub with this in your config::
    c.JupyterHub.services = [
        {
            'name': 'cull-idle',
            'admin': True,
            'command': 'python3 cull_idle_servers.py --timeout=3600'.split(),
        }
    ]
Or run it manually by generating an API token and storing it in `JUPYTERHUB_API_TOKEN`:
    export JUPYTERHUB_API_TOKEN=`jupyterhub token`
    python3 cull_idle_servers.py [--timeout=900] [--url=http://127.0.0.1:8081/hub/api]
This script uses the same ``--timeout`` and ``--max-age`` values for
culling users and users' servers.  If you want a different value for
users and servers, you should add this script to the services list
twice, just with different ``name``s, different values, and one with
the ``--cull-users`` option.
"""

# env vars:
#.   JUPYTERHUB_SERVICE_NAME
#.   JUPYTERHUB_SERVICE_URL
#.   JUPYTERHUB_SERVICE_PREFIX

#.   JUPYTERHUB_API_TOKEN
#.   JUPYTERHUB_ADMIN_ACCESS
#.   JUPYTERHUB_CLIENT_ID
#.   JUPYTERHUB_COOKIE_OPTIONS
#.   JUPYTERHUB_HOST
#.   JUPYTERHUB_OAUTH_CALLBACK_URL
#.   JUPYTERHUB_USER
#.   JUPYTERHUB_API_URL
#.   JUPYTERHUB_BASE_URL

# required here:
#.   JUPYTERHUB_API_URL ... talk to internal hub api
#.   JUPYTERHUB_BASE_URL ... talk to notebook servers
#.   JUPYTERHUB_API_TOKEN ... access the API
#.


from datetime import datetime, timezone
from email.headerregistry import Address
from email.parser import Parser
from functools import partial
import json
import logging
import os
import smtplib

try:
    from urllib.parse import quote, urljoin
except ImportError:
    from urllib import quote, urljoin

import dateutil.parser

from oauthlib.oauth2 import BackendApplicationClient
from oauthlib.oauth2 import InvalidGrantError, TokenExpiredError
from requests_oauthlib import OAuth2Session

from tornado.gen import multi
from tornado.locks import Semaphore
from tornado.log import app_log
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPClientError
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.options import define, options, parse_command_line


def parse_date(date_string):
    """Parse a timestamp
    If it doesn't have a timezone, assume utc
    Returned datetime object will always be timezone-aware
    """
    dt = dateutil.parser.parse(date_string)
    if not dt.tzinfo:
        # assume naïve timestamps are UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def format_td(td):
    """
    Nicely format a timedelta object
    as HH:MM:SS
    """
    if td is None:
        return "unknown"
    if isinstance(td, str):
        return td
    seconds = int(td.total_seconds())
    h = seconds // 3600
    seconds = seconds % 3600
    m = seconds // 60
    seconds = seconds % 60
    return "{h:02}:{m:02}:{seconds:02}".format(h=h, m=m, seconds=seconds)


def human_seconds(seconds):
    """Format timedelta skipping seconds.
    """
    if seconds is None:
        return "unknown"
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    hours, minutes = int(hours), int(minutes)
    parts = []
    if hours:
        if hours == 1:
            parts.append('{h} hour'.format(h=hours))
        else:
            parts.append('{h} hours'.format(h=hours))
    if minutes:
        if minutes == 1:
            parts.append('{m} minute'.format(m=minutes))
        else:
            parts.append('{m} minutes'.format(m=minutes))
    return ' and '.join(parts)


class Keycloak(object):
    # TODO: would be nice if this was async as well

    def __init__(self, baseurl, realm, client_id, client_secret):
        self.token_url = '{baseurl}/realms/{realm}/protocol/openid-connect/token'.format(
            baseurl=baseurl, realm=realm,
        )
        adminurl = '{baseurl}/admin/realms/{realm}'.format(
            baseurl=baseurl, realm=realm
        )
        self.user_url = '{adminurl}/users/{userid}'.format(adminurl=adminurl, userid='{userid}')

        self.client_id = client_id
        self.client_secret = client_secret

        client = BackendApplicationClient(client_id)
        self.session = OAuth2Session(
            client=client,
            scope=['openid'],  # , 'email', 'profile', 'offline_access'
            auto_refresh_url=self.token_url,
            auto_refresh_kwargs={
                'client_id': client_id,
                'client_secret': client_secret
            },
            token_updater=lambda tok: None
        )
        self._fetch_token()

    def _fetch_token(self):
        # get initital token
        self.session.fetch_token(
            self.token_url,
            client_id=self.client_id, client_secret=self.client_secret,
            scope=self.session.scope
        )

    def _get_userinfo(self, userid):
        user_url = self.user_url.format(userid=userid)
        res = self.session.get(user_url)
        res.raise_for_status()
        return res.json()

    def get_email_for_user(self, userid):
        tries = 2
        while tries:
            try:
                userinfo = self._get_userinfo(userid)
                app_log.debug('Userinfo for %s: %s', userid, userinfo)
                if not userinfo.get('email', '').strip():
                    raise Exception('No email configured for user %s', userid)
                return Address(
                    display_name=userinfo.get('display_name', ''),
                    addr_spec=userinfo['email']
                )
            except InvalidGrantError as e:
                # log this error
                app_log.error("Invalid Grant Error %s", e)
                self._fetch_token()
                tries -= 1
            except TokenExpiredError as e:
                # our refreshtoken is gone :(
                app_log.error("Token Expired Error %s", e)
                self._fetch_token()
                tries -= 1


class Mailer(object):

    def __init__(self, host, port=0, template=None, use_ssl=False):
        self.host = host
        self.use_ssl = use_ssl
        self.port = port
        self.template = template

    def send_email(self, email, params):
        # build message
        if not self.host:
            # skip
            return
        if self.template:
            content = open(self.template).read()
        else:
            content = (
                "From: ecocloud Support <support@ecocloud.org.au>\n"
                "Subject: Inactive Server will be shutdown.\n"
                "\n"
                "Your Notebook Server at {serverurl} has been idle for {inactive} and will be shutdown "
                "in {remaining}.\n"
                "\n"
                "This is an automated message."
            )
        msg = Parser().parsestr(content.format(**params))
        # TODO: add no-reply address only if we have a contact link in the mail itself.
        # msg['reply-to'] = Address(
        #     self.sender.display_name,
        #     'no-reply',
        #     self.sender.domain
        # )
        msg['To'] = str(email)
        # send email
        if self.use_ssl:
            smtp = smtplib.SMTP_SSL(self.host, self.port)
        else:
            smtp = smtplib.SMTP(self.host, self.port)

        #smtp.login(user, pass)
        #smtp.starttls()

        smtp.send_message(msg)
        smtp.quit()


# if we add a user here, send a warning email,...
# if no longer warned, remove user from here,...
# if already in here, just ignore it (already warned)
# if culled, we can remove, but don't have to...
# only add if warning succeeded.
WARNED_USER = set()
KC = None
MAILER = None


def send_email(user, server):
    try:
        WARNED_USER.add(user['name'])
        email = KC.get_email_for_user(user['name'])
        if email is not None:
            MAILER.send_email(email, server)
            app_log.info('notify %s - %s done', user['name'], email)
        else:
            app_log.warning('No valid email address to notify %s - %s.', user['name'], email)
    except Exception as e:
        app_log.error('Send email notify failed: %s', e)
        WARNED_USER.discard(user['name'])


def should_warn(user, warn_timeout, inactive):
    # TODO: in case of server restart, we potentially send out email again :(
    #       need either add persistent storage for WARNED_USER (where? volume or db?)
    #       or add some sort of leeway (may miss emails if server restart takes to long)
    # should we warn?
    app_log.info('Server %s inactive for %s', user['name'], inactive.total_seconds())
    if warn_timeout and (inactive is not None and inactive.total_seconds() >= warn_timeout):
        if user['name'] not in WARNED_USER:
            return True
    else:
        WARNED_USER.discard(user['name'])
    return False


async def cull_idle(api_url, base_url, api_token,
                    inactive_limit, max_age=0, warn_timeout=0,
                    concurrency=10, verify_ssl=True):
    """Shutdown idle single-user servers
    If cull_users, inactive *users* will be deleted as well.
    """
    auth_header = {
        'Authorization': 'token %s' % api_token,
    }
    req = HTTPRequest(
        url=api_url + '/users',
        headers=auth_header,
        validate_cert=verify_ssl,
    )
    now = datetime.now(timezone.utc)
    client = AsyncHTTPClient()

    if concurrency:
        semaphore = Semaphore(concurrency)

        async def fetch(req):
            """client.fetch wrapped in a semaphore to limit concurrency"""
            await semaphore.acquire()
            try:
                return (await client.fetch(req))
            finally:
                semaphore.release()
    else:
        fetch = client.fetch

    # tornado.curl_httpclient.CurlError: HTTP 599: Connection timed out after 20003 milliseconds
    # Potential timeout error here? (slow to stop line: 478)
    resp = await fetch(req)
    users = json.loads(resp.body.decode('utf8', 'replace'))
    futures = []

    async def get_server_active(server):
        server_url = urljoin(base_url, server['url'])
        app_log.debug('Server url: %s', server_url)

        if server.get('started'):
            age = now - parse_date(server['started'])
        else:
            # started may be undefined on jupyterhub < 0.9
            age = None

        # check server status
        num_kernels = 0
        try:
            # status query does not change last_activity on notebook server
            req = HTTPRequest(
                url=urljoin(server_url, 'api/status'),
                headers=auth_header,
                validate_cert=verify_ssl,
            )
            resp = await fetch(req)
            status = json.loads(resp.body.decode('utf-8', 'replace'))
            # app_log.info(status)
            inactive = [now - parse_date(status['last_activity'])]
            num_kernels = status['kernels']
        except HTTPClientError as e:
            app_log.error('Failed to get notebook status: %s', e)
            # make sure inactive is defined
            inactive = [age]

        # if an error happened, then num_kernels is still 0
        # TODO: for now kernel activity tracking is deactivated
        # code below is problematic ... it triggers an update of last activity on
        # the notebook server ... also should look into other activites like open shell (process?)
        # a busy cell that finishes updates last_activity as well
        # Also it seems, that a user has to keep the notebook in an open tab visible/foreground ....
        #.   putting tab a side does not help.not
        #.   minifing browser window neither or moving off screen neither.
        #    hiding browser window with anothe window stops refreshing as well
        #.   jupyterlab stops polling if document.hidden is true (old interface doesn't poll at all)
        #.   -> we could also hook into here ... and add a 'keep-alive' extension, that keeps polling (at a slower interval or so?)
        # TODO: to make this more reliable, we should install a notebook api/service extension,
        #.      that tracks all the activity we want. This allows us to use the internal
        #       notebook API and container/host process inspection to look at more things as well
        if not num_kernels:
            # no kernel running
            return True, min(inactive), age

        # FIXME: hardcoded skip rest of activity checking
        return True, min(inactive), age

        # assume everything is idle
        idle = True
        # kernels:
        # TODO: we ar ecalling through the proxy here.... which will update
        #       the hubs view of inactivity :(
        if app_log.isEnabledFor(logging.DEBUG):
            app_log.debug('Query kernels %s', urljoin(server_url, 'api/kernels'))
        req = HTTPRequest(
            url=urljoin(server_url, 'api/kernels'),
            headers=auth_header,
            validate_cert=verify_ssl,
        )
        try:
            resp = await fetch(req)
            kernels = json.loads(resp.body.decode('utf-8', 'replace'))
            for kernel in kernels:
                # TODO: seems like kernel state stays in 'starting' after a restart and auto
                #       re-creation of running kernels from last ui state
                idle = idle and (kernel['execution_state'] in ('idle', 'starting'))
                inactive.append(now - parse_date(kernel['last_activity']))
        except HTTPClientError as e:
            app_log.error('Falid to inspect notebook kernels: %s', e)
        # find smallest inactive time
        return idle, min(inactive), age

    async def handle_server(user, server_name, server):
        """Handle (maybe) culling a single server
        Returns True if server is now stopped (user removable),
        False otherwise.
        """
        # import ipdb; ipdb.set_trace()
        log_name = user['name']
        if server_name:
            log_name = '%s/%s' % (user['name'], server_name)
        if server.get('pending'):
            app_log.warning(
                "Not culling server %s with pending %s",
                log_name, server['pending'])
            return False

        # jupyterhub < 0.9 defined 'server.url' once the server was ready
        # as an *implicit* signal that the server was ready.
        # 0.9 adds a dedicated, explicit 'ready' field.
        # By current (0.9) definitions, servers that have no pending
        # events and are not ready shouldn't be in the model,
        # but let's check just to be safe.

        if not server.get('ready', bool(server['url'])):
            app_log.warning(
                "Not culling not-ready not-pending server %s: %s",
                log_name, server)
            return False

        idle, inactive, age = await get_server_active(server)
        if not idle and app_log.isEnabledFor(logging.DEBUG):
            # something is not idle
            # when the kernel transitions from busy to idle, the kernel resets the
            # inactive timer as well.
            app_log.debug(
                'Not culling server %s with busy connections. (inactive for %s)',
                log_name, inactive)
            return

        should_cull = (inactive is not None and
                       inactive.total_seconds() >= inactive_limit)
        if should_cull:
            app_log.info(
                "Culling server %s (inactive for %s)",
                log_name, format_td(inactive))

        if max_age and not should_cull:
            # only check started if max_age is specified
            # so that we can still be compatible with jupyterhub 0.8
            # which doesn't define the 'started' field
            if age is not None and age.total_seconds() >= max_age:
                app_log.info(
                    "Culling server %s (age: %s, inactive for %s)",
                    log_name, format_td(age), format_td(inactive))
                should_cull = True

        # should we warn?
        remaining = inactive_limit - inactive.total_seconds()
        if should_warn(user, warn_timeout, inactive) and remaining > 0:
            IOLoop.current().run_in_executor(
                None,
                send_email,
                user,
                {
                    'serverurl': urljoin(base_url, server['url']),
                    'inactive': human_seconds(inactive.total_seconds()),
                    'remaining': human_seconds(remaining),
                }
            )

        if not should_cull:
            app_log.debug(
                "Not culling server %s (age: %s, inactive for %s)",
                log_name, format_td(age), format_td(inactive))
            return False

        if server_name:
            # culling a named server
            delete_url = api_url + "/users/%s/servers/%s" % (
                quote(user['name']), quote(server['name'])
            )
        else:
            delete_url = api_url + '/users/%s/server' % quote(user['name'])

        req = HTTPRequest(
            url=delete_url, method='DELETE', headers=auth_header,
            validate_cert=verify_ssl,
        )
        resp = await fetch(req)
        if resp.code == 202:
            app_log.warning(
                "Server %s is slow to stop",
                log_name,
            )
            # return False to prevent culling user with pending shutdowns
            return False
        return True

    async def handle_user(user):
        """Handle one user.
        Create a list of their servers, and async exec them.  Wait for
        that to be done, and if all servers are stopped, possibly cull
        the user.
        """
        # shutdown servers first.

        servers = user['servers']
        server_futures = [
            handle_server(user, server_name, server)
            for server_name, server in servers.items()
        ]
        results = await multi(server_futures)

    for user in users:
        futures.append((user['name'], handle_user(user)))

    for (name, f) in futures:
        try:
            result = await f
        except Exception:
            app_log.exception("Error processing %s", name)
        else:
            if result:
                app_log.debug("Finished culling %s", name)

    # IOLoop.current().stop()


if __name__ == '__main__':
    define(
        'api_url',
        default=os.environ.get('JUPYTERHUB_API_URL'),
        help="The JupyterHub API URL",
    )
    define(
        'base_url',
        default=os.environ.get('JUPYTERHUB_BASE_URL'),
        help=("The JupyterHub external base URL (to access notebook servers), "
              "this has to be the external name otherwise email will have "
              "wrong link."),
    )
    define('timeout', default=600, help="The idle timeout (in seconds)")
    define('cull_every', default=0,
           help=("The interval (in seconds) for checking for idle servers to "
                 "cull"),
           )
    define('max_age', default=0,
           help=("The maximum age (in seconds) of servers that should be "
                 "culled even if they are active"),
           )
    define('concurrency', default=10,
           help=("Limit the number of concurrent requests made to the Hub. "
                 "Deleting a lot of users at the same time can slow down the "
                 "Hub, so limit the number of API requests we have "
                 "outstanding at any given time."),
           )
    define('warn_timeout', default=0,
           help=("The idle timeout to warn users before culling a server. "
                 "(in seconds)"),
           )
    define('smtp_host', default=None,
           help=("Smtp server to use to send out email to warn users before "
                 "their notebook will be culled."),
           )
    define('smtp_port', default=0,
           help=("Smtp server to use to send out email to warn users before "
                 "their notebook will be culled."),
           )
    define('mail_template', default=None,
           help="Mail template file.",
           )
    define('keycloak_base_url',
           default=os.environ.get('KEYCLOAK_BASE_URL', ''),
           help="Keycloak base url: http://keycloak.example.com/auth")
    define('keycloak_realm',
           default=os.environ.get('KEYCLOAK_REALM', ''),
           help="Keycloak realm")
    define('keycloak_client_id',
           default=os.environ.get('KEYCLOAK_CLIENT_ID', ''),
           help="Keycloak client id")
    define('keycloak_client_secret',
           default=os.environ.get('KEYCLOAK_CLIENT_SECRET', ''),
           help="Keycloak client secret")
    define('debug',
           default=False,
           help="Enable Debug log")
    define('disable_ssl_verify',
           default=False,
           help="Disable SSL verification for all hub and notebook requests.")

    parse_command_line()
    if not options.cull_every:
        options.cull_every = options.timeout // 2
    api_token = os.environ['JUPYTERHUB_API_TOKEN']

    if options.debug:
        app_log.setLevel(logging.DEBUG)

    try:
        AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")
    except ImportError as e:
        app_log.warning(
            "Could not load pycurl: %s\n"
            "pycurl is recommended if you have a large number of users.",
            e)

    # init keycloak client
    KC = Keycloak(
        options.keycloak_base_url,
        options.keycloak_realm,
        client_id=options.keycloak_client_id,
        client_secret=options.keycloak_client_secret
    )
    # init Mailer
    MAILER = Mailer(
        options.smtp_host, options.smtp_port,
        options.mail_template
    )

    loop = IOLoop.current()
    cull = partial(
        cull_idle,
        api_url=options.api_url,
        base_url=options.base_url,
        api_token=api_token,
        inactive_limit=options.timeout,
        max_age=options.max_age,
        warn_timeout=options.warn_timeout,
        concurrency=options.concurrency,
        verify_ssl=not options.disable_ssl_verify,
    )
    # schedule first cull immediately
    # because PeriodicCallback doesn't start until the end of the first interval
    loop.add_callback(cull)
    # schedule periodic cull
    pc = PeriodicCallback(cull, 1e3 * options.cull_every)
    pc.start()
    try:
        loop.start()
    except KeyboardInterrupt:
        pass
