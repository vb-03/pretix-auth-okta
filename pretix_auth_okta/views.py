import logging
import requests
import jwt
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _
from pretix.base.models import User
from pretix.base.models.auth import EmailAddressTakenError
from pretix.control.views.auth import process_login
from pretix.helpers.urls import build_absolute_uri
from urllib.parse import quote

logger = logging.getLogger(__name__)

def start_view(request):
    request.session['pretix_auth_okta_nonce'] = get_random_string(32)
    url = (
            settings.CONFIG_FILE.get('pretix_auth_okta', 'url') +
            '/authorize?client_id={client_id}&none={nonce}&redirect_uri={redirect_uri}&state={state}&response_type=code+id_token&response_mode=query&scope=openid+profile+email'
    ).format(
        client_id=settings.CONFIG_FILE.get('pretix_auth_okta', 'client_id'),
        nonce=request.session['pretix_auth_okta_nonce'],
        state=quote(request.session['pretix_auth_okta_nonce'] + '#' + request.GET.get('next', '')),
        redirect_uri=quote(build_absolute_uri('plugins:pretix_auth_okta:return'))
    )
    return redirect(url)

def return_view(request):
    # check for error state
    if 'error' in request.GET:
        logger.warning('Okta login failed. Response: ' + request.META['QUERY_STRING'])
        messages.error(request, _('Login was not successful. Error: {message}').format(message=request.GET.get('error_description')))
        return redirect(reverse('control:auth.login'))

    if 'state' not in request.GET:
        logger.exception('Okta login did not send a state.')
        messages.error(request, _('Login was not successful due to a technical error.'))
        return redirect(reverse('control:auth.login'))

    nonce, next = request.GET['state'].split('#')
    if nonce != request.session['pretix_auth_okta_nonce']:
        logger.exception('Okta login sent an invalid nonce in the state parameter.')
        messages.error(request, _('Login request timed out, please try again.'))
        return redirect(reverse('control:auth.login'))
    if next:
        request._okta_next = next

    try:
        r = requests.post(
            settings.CONFIG_FILE.get('pretix_auth_okta', 'url') + '/token',
            data={
                'grant_type': 'authorization_code',
                'client_id': settings.CONFIG_FILE.get('pretix_auth_okta', 'client_id'),
                'client_secret': settings.CONFIG_FILE.get('pretix_auth_okta', 'client_secret'),
                'redirect_uri': build_absolute_uri('plugins:pretix_auth_okta:return'),
                'code': request.GET.get('code')
            }
        )
        r.raise_for_status()
        response = r.json()
        id_token = response['id_token']

        # Decode and verify the ID token
        key_url = "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys".format(
            tenant_id=settings.CONFIG_FILE.get('pretix_auth_okta', 'tenant_id')
        )
        keys = requests.get(key_url).json()
        public_key = keys['keys'][0]  # Assuming the first key is the one we need

        # Decode the token
        claims = jwt.decode(id_token, public_key, algorithms=['RS256'], audience=settings.CONFIG_FILE.get('pretix_auth_okta', 'client_id'))
    except (requests.RequestException, jwt.PyJWTError) as e:
        logger.exception('Azure AD login failed.')
        messages.error(request, _('Login was not successful due to a technical error.'))
        return redirect(reverse('control:auth.login'))

    try:
        u = User.objects.get_or_create_for_backend(
            'azuread', claims['oid'], claims['email'],
            set_always={},
            set_on_creation={
                'fullname': claims['name']
                #'{} {}'.format(
                   # claims.get('given_name', ''),
                   # claims.get('family_name', ''),
              #  ),
                #'locale': claims.get('locale').lower()[:2],
                #'timezone': claims.get('zoneinfo', 'UTC'),
            }
        )
    except EmailAddressTakenError:
        messages.error(
            request, _('We cannot create your user account as a user account in this system '
                       'already exists with the same email address.')
        )
        return redirect(reverse('control:auth.login'))
    else:
        return process_login(request, u, keep_logged_in=False)