class PyramidTestsA(unittest.TestCase):
    """
    fake request needs:
        dbSession
        datetime
        active_useraccount_id
    THESE AREN"T USED YET
    """
    _sa_engine = None
    _sa_sessionmaker = None
    _sa_session = None
    _sa_db = None
    _pyramid_request = None

    def _get_sa_engine(self):
        if self._sa_engine is None:
            self._sa_engine = sqlalchemy.create_engine("sqlite://", echo=False)
            oauth1_model.Base.metadata.create_all(self._sa_engine)
        return self._sa_engine

    def _get_sa_sessionmaker(self):
        if self._sa_sessionmaker is None:
            self._sa_sessionmaker = sqlalchemy.orm.sessionmaker(bind=self._get_sa_engine())  # session class
        return self._sa_sessionmaker

    def _get_sa_session(self):
        if self._sa_session is None:
            self._sa_session = self._get_sa_sessionmaker()()  # first parens gets the sessionmaker, second invokes it
        return self._sa_session

    def setUp(self):
        self._pyramid_request = new_req_session()

    def _test_foo(self):
        user = oauth1_model.Useraccount()
        dir(user)
        user.id = 1
        self._pyramid_request.dbSession.add(user)
        self._pyramid_request.dbSession.flush()