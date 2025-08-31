# stdlib
import datetime
from http.cookiejar import CookieJar
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# pypi
import webtest
import webtest.app

if TYPE_CHECKING:
    from pyramid_sqlassist.interface import TYPES_SESSION


# ==============================================================================


class FakeRegistry(object):
    """
    fake object for FakeRequest
    """

    settings = None


class FakeRequest(object):
    """
    fake object, needs FakeAppMeta
    current version
    """

    _current_route_url: Optional[str] = None
    _method: Optional[str] = None
    _post: Optional[Dict] = None
    active_useraccount_id: Optional[int] = None
    dbSession: Optional["TYPES_SESSION"] = None
    timestamp: Optional[datetime.datetime] = None
    registry: FakeRegistry
    headers: Union[Dict, List]

    def __init__(self):
        self.timestamp = datetime.datetime.utcnow()
        self.registry = FakeRegistry()
        self.headers = []

    def current_route_url(self, uri: Optional[str] = None) -> Optional[str]:
        if uri is not None:
            self._current_route_url = uri
        return self._current_route_url

    @property
    def url(self):
        return self.current_route_url()

    @property
    def method(self) -> str:
        return self._method or "GET"

    @property
    def POST(self) -> Dict:
        return self._post or {}


def parse_request_simple(req: "FakeRequest") -> Tuple[str, str]:
    if "?" in req.url:
        _path, _qs = req.url.split("?")
    else:
        _path = req.url
        _qs = ""
    return (_path, _qs)


class IsolatedTestapp(object):
    """
    This class offers a ContextManger that uses it's own cookiejar

    Requirements:
        import webtest.app

    Attributes:
        ``testapp`` active ``webtest.TestApp`` instance
        ``cookiejar_original`` original cookiejar for testapp. It will be replaced on exit.
        ``cookiejar_local`` local cookiejar to context manager.
    """

    testapp: webtest.TestApp
    cookiejar_original = None
    cookiejar_local = None

    def __init__(self, testapp: webtest.TestApp, cookiejar: Optional[CookieJar] = None):
        """
        args:
            ``testapp`` active ``webtest.TestApp`` instance
        kwargs:
            ``cookiejar`` standard library ``CookieJar`` compatible instance, or ``None`` to create an automated jar
        """
        self.testapp = testapp
        self.cookiejar_original = testapp.cookiejar
        if cookiejar is None:
            cookiejar = webtest.app.http_cookiejar.CookieJar(
                policy=webtest.app.CookiePolicy()
            )
        self.cookiejar_local = testapp.cookiejar = cookiejar

    def __enter__(self):
        return self.testapp

    def __exit__(self, *args):
        self.testapp.cookiejar = self.cookiejar_original
