pyramid_oauthlib_lowlevel
=========================

![Python package](https://github.com/jvanasco/pyramid_oauthlib_lowlevel/workflows/Python%20package/badge.svg)

This is a package designed to create oAuth servers with Pyramid through a lowlevel interface that allows for more customization.

Before using this package I suggest you consider the package `pyramid-oauthlib`, it is possibly better suited to your needs as it offers a highlevel interface.

Seriously. This package provides a very lowlevel interface to customizing the `oauthlib` package within Pyramid.  Most people will want to use the higher level abstractions with a more simplified package.

What do I mean by highlevel vs lowlevel?

highlevel: `pyramid-oauthlib` makes a lot of hard decisions for you, and gives you a handful of hooks to easily implement oAuth flows into your Pyramid application.  You don't need to know much about oAuth to utilize it.

lowlevel: `pyramid-oauthlib-lowlevel` provides a very basic integration scheme for leveraging the oauthlib library in Pyramid applications.  You generally need to know quite a bit about oAuth to handle this.

Some use-cases for this package are situations where:

1. You need to support oAuth1. (`pyramid-oauthlib` only supports oAuth2)
2. You need more fine-grained control over the oAuth2 integration or to host multiple oAuth2 servers. `pyramid-oauthlib` expects you to be doing things a certain way (which is very common and the status-quo).
3. You need to support/create broken oAuth servers.*

* Broken oAuth servers? Yes. Even major internet services often implement oAuth in ways that do not fully adhere to the specs, or violate them. Offline integrated test suites may need to create servers which can mimic this behavior.

The package generally works by defining one or more subclasses to handle getting/setting data objects, then invoking them on Pyramid requests via explicitly designed oAuth providers.

This approach will allow you to create multiple oAuth servers and/or authentication methods running on the same Pyramid server

The rational for developing with this approach was a need to:
1. support multiple oAuth versions and endpoints on a whitelabel service
2. limit and isolate the oAuth data from the Pyramid request.

This project was largely modeled after `flask-oauthlib` and the core `oauthlib` package. Docstrings in this package are taken from both.  Significant portions of code in this package are a port of `flask-oauthlib` to `Pyramid`; many portions adapt bits straight from `oauthlib` as well.


How This Package is Generally Designed
======================================

Both `oauth1` and `oauth2` namespaces offer a `provider` and `validator` namespace.

The `oauth1.validator.OAuth1RequestValidator_Hooks` and `oauth2.validator.OAuth2RequestValidator_Hooks` classes provide hooks for the `RequestValidator` to get/set data from your database and cache. In every deployment these must be subclassed.

The `oauth1.validator.OAuth1RequestValidator` and `oauth2.validator.OAuth2RequestValidator` classes provide the logic used to handle oAuth requests, adapted to Pyramid. Only in rare cases should these be subclassed.

The `oauth1.provider.OAuth1Provider` and `oauth2.provider.OAuth2Provider` provide methods which invoke the `RequestValidator` under Pyramid endpoints as logical units of work that are either endpoints or resource validators. Only in rare cases should these be subclassed.

* `oauth1.provider.OAuth1Provider`
 * `.endpoint__request_token`
 * `.endpoint__access_token`
 * `.extract__endpoint_authorize_data`
 * `.endpoint__authorize__authorize`
 * `.logic__is_authorized`

* `oauth2.provider.OAuth2Provider`
 * `.endpoint__validate_authorization_request`
 * `.endpoint__confirm_authorization_request`
 * `.endopoint__token`
 * `.endpoint__revoke_token`
 * `.verify_request`

Typically usage will involve these steps:

* subclass a `hooks` object in the application
* on a request, first create a new instance of a `provider` with the customized hook
* on a request, then invoke the desired endpoint or request validation.


Example Applications
====================

The [OAuth1](tests/oauth1_app) and [OAuth2](tests/oauth2_app) test applications
show how to connect Pyramid endpoints to the providers and implement the
storage hooks. The [OAuth1 flow](docs/oauth1/flow.md) walks through the
request-token, authorization, and access-token exchange.

The integration tests cover OAuth1 authorization and OAuth2 authorization
code, client credentials, refresh, and revocation. See [TESTING.txt](TESTING.txt)
for test commands and the OAuthlib compatibility checks.

Tutorial
===============


Here is a quick way to design an oAuth server:

1. Subclass OAuth1RequestValidator

	# this is optional

	class CustomValidator(OAuth1RequestValidator):
		"""some validator methods do need overrides."""

		@property
		def realms(self):
			return ['platform.actor', ]

		@property
		def client_key_length(self):
			return (40, 64)

		...

2. Subclass OAuth1RequestValidator_Hooks

	# the library provides a `@catch_backend_failure` to wrap backend failures with more meaning

	class CustomValidator_Hooks(OAuth1RequestValidator_Hooks):
		"""
		This custom object expects a SqlAlchemy connection on `self.pyramid_request.dbSession`
		"""

		@catch_backend_failure
		def _get_TokenRequest_by_verifier(self, verifier, request=None):
			"""
			:param verifier: The verifier string.
			:param request: An oauthlib.common.Request object.
			"""
			verifierObject = sqla.get_Developer_oAuth1Server_TokenRequest__by_oauthVerifier(
				self.pyramid_request.dbSession,
				verifier,
			)
			return verifierObject

3. Create an oAuth object

	# this might be a request property via @reify
	
	def new_oauth1Provider(request):
		"""this is used to build a new auth"""
		validatorHooks = CustomValidator_Hooks(request)
		provider = pyramid_oauthlib_lowlevel.oauth1.provider.OAuth1Provider(request,
																			validator_api_hooks = validatorHooks,
																			validator_class = CustomValidator
																			)
		return provider

4. Use the oAuth object - Checking for API access

	# Within your authorization routines, you can check for a valid oauth request

	oauth1Provider = new_oauth1Provider(request)
	_is_authorized, req = oauth1Provider.logic__is_authorized(['platform.actor', ])
	if not _is_authorized:
		raise HTTPUnauthorized(body="""'{"error": "Not Authorized (oAuth Failed)}'""", content_type='application/json')
	# perhaps do something with `req.client` and `req.access_token_object`
	
	
5. Use the oAuth object - routes for granting access

	See the testapps


Integration
===============

Because this is a `_lowlevel` library, there is no automagic integration of this package into Pyramid.

In the example apps, convenience methods are used to create an oauth provider as needed:

	def new_oauth2Provider(pyramid_request):
		validatorHooks = CustomValidator_Hooks(pyramid_request)
		provider = oauth2_provider.OAuth2Provider(pyramid_request,
												  validator_api_hooks = validatorHooks,
												  validator_class = CustomValidator
												  )
		return provider

A deployment might handle this as part of Pyramid AUTH, within Tweens or Middleware, as a request property, or many other options.

The oauth2 testapp has a particular flow worth noting:

`ExampleApp.fetch_protected_resource` A user must log into ExampleApp and have an authorized token for the Authority system.  This route will load the token and use it to make an oAuth2 request against the Authority system.

`Authority_Oauth2_API_Public.protected_resource`  The resource is protected behind an oauth2 token validation.

	    oauth2Provider = new_oauth2Provider(self.request)
        scopes = ['platform.actor', ]
        valid, req = oauth2Provider.verify_request(scopes)


oAuth Flows
======================================

There are many different flows one can do in oAuth

This project is currently aimed at implementing the following families of flows:

* Flow-AccountRegistration - a user of `Authority` establishes a new account on `Application`
* Flow-AccountBind - an existing user of `Application` links their account to `Authority`
* Flow-Developer - a user of `Authority` has created an `Application` and needs an access token


Notes on Token Expiration and Refresh
=====================================

There are several strategies and concerns for expiring access and refresh tokens during a refresh.

Some deployments wish to expire all access tokens for a user when a new access_token is generated.

This is illustrated in `oauth2_utils.OAuth2RequestValidator_Hooks.bearer_token_setter`, which sets existing live tokens for a user/client as inactive.

Some deployments will not want to do this, such as cloud based systems which may take some time to propagate new credentials. 

Some deployments will wish to recycle a `refresh_token` across multiple access_token refreshes.  This is supported by overriding a default method in `OAuth2RequestValidator`

	class CustomValidator(OAuth2RequestValidator):

		def rotate_refresh_token(self, request):
			"""Determine whether to rotate the refresh token. Default, yes.

			When access tokens are refreshed the old refresh token can be kept
			or replaced with a new one (rotated). Return True to rotate and
			and False for keeping original.

			:param request: oauthlib.common.Request
			:rtype: True or False

			Method is used by:
				- Refresh Token Grant
			"""
			return False


Both forms are covered in the test suite (the default is overridden by monkeypatching the Request Validator, then it is reset)

Some deployments will want to DELETE a token when it expires or is revoked.  This library is designed to support using database flags to mark if a token is active, revoked, expired, etc.  This is designed for concerns in bookkeeping.

Notes on Refreshing Tokens
==========================

OAuthlib is an excellent library, but there are some minor inconveniences you may need to look out for when refreshing a token.

1. OAuthlib does not cache the refresh_token's object, it merely validates it or it's parameters.  Unless you specifically cache it, you may load it multiple times in a single request for each validation operation.  Many packages that utilize OAuthlib do not account for this implementation detail - this package included.

2. OAuthlib does not maintain the lineage of a token across refreshes. This is important if your application supports more than one type of grant (such as supporting both `authorization_code` AND `client_credentials`).  To get around this, we recommend doing the following:

 * extend the storage for tokens with the following fields:
  * `grant_type`
  * `original_grant_type`
 * extend `bearer_token_setter` to do the following:
  * store the `request.grant_type` onto the new token object when you save it to the database.
  * if the `grant_type` is not "refresh_token", store that value as the `original_grant_type`
  * if the `grant_type` is "refresh_token", then load the "refresh_token" object (request.refresh_token), and copy the `original_grant_type`

This strategy will allow you to easily differentiate between client_credential (Application) and authorization_code (User) tokens.


Python Compatibility
====================

Version 1.0.0 supports Python 3.7 and later and requires OAuthlib 3.2.2
or later. The test matrix covers Python 3.7 through 3.15. Maintaining
legacy compatibility lets applications adopt these fixes on their existing
Python and OAuthlib versions.

Storage Hook Requirements
=========================

- **OAuth1 nonce claims.** The nonce setter must claim the nonce atomically in
  shared storage, using the same identity as the getter. Return `False`
  when the claim is rejected. Successful legacy setters may still return
  `None`. See [OAuth1 nonce storage](docs/oauth1/flow.md#nonce-storage).
- **OAuth2 grants.** Look up active authorization codes by both client ID
  and code. If the returned grant exposes `client_id`, the validator checks
  it against the requested client. Refresh-token records must expose their
  issuing client's ID.
- **OAuth2 tokens.** Return only active tokens from storage. A bearer token
  must include every scope required by the resource. The revocation hook
  receives a token owned by the requesting client and must make it
  unavailable to subsequent lookups.

`OAuth2RequestValidator` integrates OAuthlib's base OAuth2 validator. OAuthlib
defines its OpenID Connect-specific hooks on its OpenID Connect validator.

License
=======

Some functions are ported from oauthlib and flask-oauthlib;
see LICENSE.txt

Some functions are ported from Pyramid and appear under their License;
see LICENSE-Pyramid.txt




