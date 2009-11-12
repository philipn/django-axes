from django.conf import settings
from django.contrib.auth import logout
from axes.models import AccessAttempt
from django.http import HttpResponse
import axes
import logging

# see if the user has overridden the failure limit
if hasattr(settings, 'LOGIN_FAILURE_LIMIT'):
    FAILURE_LIMIT = settings.LOGIN_FAILURE_LIMIT
else:
    FAILURE_LIMIT = 3

# see if the user has overridden the failure reset setting
if hasattr(settings, 'LOGIN_FAILURE_RESET'):
    FAILURE_RESET = settings.LOGIN_FAILURE_RESET
else:
    FAILURE_RESET = True

# see if the user has set axes to lock out logins after failure limit
if hasattr(settings, 'LOCK_OUT_AT_FAILURE'):
    LOCK_OUT_AT_FAILURE = True
    FAILURE_RESET = False # this is necessary
else:
    LOCK_OUT_AT_FAILURE = False

if hasattr(settings, 'LOGIN_FAILURE_BY_USER_AGENT'):
    USE_USER_AGENT = True
else:
    USE_USER_AGENT = False

def query2str(items):
    return '\n'.join(['%s=%s' % (k, v) for k,v in items])

log = logging.getLogger('axes.watch_login')
log.info('BEGIN LOG')
log.info('Using django-axes ' + axes.get_version())

def watch_login(func, failures):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    def decorated_login(request, *args, **kwargs):
        # share some useful information
        if func.__name__ != 'decorated_login':
            log.info('Calling decorated function: %s' % func)
            if args: log.info('args: %s' % args)
            if kwargs: log.info('kwargs: %s' % kwargs)

        # call the login function
        response = func(request, *args, **kwargs)

        if func.__name__ == 'decorated_login':
            # if we're dealing with this function itself, don't bother checking
            # for invalid login attempts.  I suppose there's a bunch of
            # recursion going on here that used to cause one failed login
            # attempt to generate 10+ failed access attempt records (with 3
            # failed attempts each supposedly)
            return response

        if request.method == 'POST':
            # see if the login was successful
            login_unsuccessful = (
                response and
                not response.has_header('location') and
                response.status_code != 302
            )
            ip = request.META.get('REMOTE_ADDR', '')
            if USE_USER_AGENT:
                ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
            else:
                ua = ''
            key = '%s:%s' % (ip, ua)
            if login_unsuccessful:
                log.debug('Failure dict (begin): %s' % failures)
                
                # make sure we have an item for this key
                try:
                    failures[key]
                    log.debug('Key %s exists' % key)
                except KeyError:
                    log.debug('Creating key %s' % key)
                    failures[key] = 0

                # add a failed attempt for this user
                failures[key] += 1

                log.info('Adding a failure for %s; %i failure(s)' % (key, failures[key]))
                #log.debug('Request: %s' % request)

                log.debug('Failure dict (end): %s' % failures)
                log.info('-' * 79)

            # if we reach or surpass the failure limit, create an
            # AccessAttempt record
            if failures[key] >= FAILURE_LIMIT:
                log.info('=================================')
                log.info('Creating access attempt record...')
                log.info('=================================')
                attempt = AccessAttempt.objects.create(
                    user_agent=ua,
                    ip_address=ip,
                    get_data=query2str(request.GET.items()),
                    post_data=query2str(request.POST.items()),
                    http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
                    path_info=request.META.get('PATH_INFO', '<unknown>'),
                    failures_since_start=failures[key]
                )

                if FAILURE_RESET and login_unsuccessful:
                    del(failures[key])

                if LOCK_OUT_AT_FAILURE:
                    response = HttpResponse("Account locked: too many login attempts.  "
                                            "Contact an admin to unlock your account."
                                                 )
                    # We log them out in case they actually managed to enter
                    # the correct password.
                    logout(request)

        return response
    return decorated_login
