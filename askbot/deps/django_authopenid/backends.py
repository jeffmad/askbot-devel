"""authentication backend that takes care of the
multiple login methods supported by the authenticator
application
"""
import datetime
import logging
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings as django_settings
from django.utils.translation import ugettext as _
from askbot.deps.django_authopenid.models import UserAssociation
from askbot.deps.django_authopenid import util
from askbot.deps.django_authopenid.ldap_auth import ldap_authenticate
from askbot.deps.django_authopenid.ldap_auth import ldap_create_user
from askbot.conf import settings as askbot_settings
from askbot.signals import user_registered

LOG = logging.getLogger(__name__)
from django.conf import settings

log = logging.getLogger('configuration')

def ldap_expedia_authenticate(username, password):
    """
    Authenticate using ldap
    expedia ldap does not allow anon lookups
    there is a service acct 
    python-ldap must be installed
    http://pypi.python.org/pypi/python-ldap/2.4.6
    """
    import ldap
    l = ldap.initialize(askbot_settings.LDAP_URL)
    logging.critical('authenticating with ldap')
    # add this because windows gives error
    l.set_option(ldap.OPT_REFERRALS,0)
    user =  settings.LDAP_USER
    pwd = settings.LDAP_PASSWORD
    try:
        l.simple_bind_s(user,pwd)
    except ldap.LDAPError, e:
        logging.critical('caught ldapError binding. user={0}, server={1}, error={2}'.format(user, serverName, e.message['info']))
        if type(e.message) == dict and e.message.has_key('desc'):
            logging.critical('x caught ldap error: {0}'.format(e.message['desc']))
        else:
            logging.critical('ldap error {0}'.format(repr(e)))
    scope = ldap.SCOPE_SUBTREE
    base = settings.LDAP_BASE
    keyword = username
    filter = '(&(objectclass=user)(sAMAccountName=' + keyword + '))'
    retrieve_attributes = ['displayName', 'mail']
    # if retrieve_attributes = None then all will be returned
    #retrieve_attributes = None
    count = 0
    result_set = []
    timeout = 0
    fullName = ''
    mail = ''
    try:
        result_id = l.search(base, scope, filter, retrieve_attributes)
        #print 'result is: ' + repr(result_id)
        while 1:
            result_type, result_data = l.result(result_id, timeout)
            if(result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
        if len(result_set) == 0:
            logging.debug('No results found for user={0}'.format(username))
            return None;
        else:
            for i in range(len(result_set)):
                for entry in result_set[i]:
                    # what comes back is a tuple len 2
                    # first entry is string DN used for next query
                    # second entry is a map. one key per 
                    # retrieve attribute. the corresponding value
                    # for the key is a list with len = 1
                    dn = entry[0]
                    fullName = entry[1]['displayName'][0]
                    mail = entry[1]['mail'][0]
                    #mail = '{0}@expedia.com'.format(entry[1]['mail'][0])
                    #print 'dn ={0}'.format(dn)
                    #print 'displayName ={0}'.format(fullName)
                    #print 'email ={0}'.format(mail)
                    #print 'result: ' + repr(entry) + '\n'
    except ldap.LDAPError, error_message:
        logging.critical('caught errorin ldap results: {0} while querying username = {1} '.format(str(error_message, username)))
        return None;
    try:
        # now that we have a DN, we can try to bind with it, 
        # along with the user provided password
        # a DN looks like this: 'CN=John Smith (jsmith),OU=User Policy 0,OU=All Users,DC=DET,DC=CORP,DC=MSFTCN,DC=com'
        l.bind_s(dn, password)
        logging.error('logon success, now looking up user in db')
        try:
            user = User.objects.get(email=mail)
            # always update user profile to synchronize with ldap server
            logging.error('found user')
            user.username = username
            #user.set_password('')
            #user.first_name = ''#first_name
            #user.last_name = ''#last_name
            #user.email = mail
            user.save()
        except User.DoesNotExist:
            # create new user in local db
            logging.error('did not find user, creating')
            user = User()
            user.username = username
            user.set_password('')
            user.first_name = ''#first_name
            user.last_name ='' # last_name
            user.email =  mail
            user.is_staff = False
            user.is_superuser = False
            user.is_active = True
            user.save()
        logging.info('Created New User : [{0}]'.format(username))
        return user
    except ldap.LDAPError, error_message:
        logging.debug('user {0} incurred LDAPError: {1} '.format(username, str(error_message)))
        return None
    except ldap.INVALID_CREDENTIALS, error_message:
        logging.debug('user {0} presented invalid credentials: {1} '.format(username, str(error_message)))
        return None
    except Exception, error_message:
        logging.debug('user {0} encountered generic exception: {1} '.format(username, str(error_message)))
        return None

    finally:
        l.unbind_s()


def ldap_authenticate(username, password):
    """
    Authenticate using ldap
    
    python-ldap must be installed
    http://pypi.python.org/pypi/python-ldap/2.4.6
    """
    import ldap
    user_information = None
    try:
        ldap_session = ldap.initialize(askbot_settings.LDAP_URL)
        ldap_session.protocol_version = ldap.VERSION3
        user_filter = "({0}={1})".format(askbot_settings.LDAP_USERID_FIELD, 
                                         username)
        # search ldap directory for user
        res = ldap_session.search_s(askbot_settings.LDAP_BASEDN, ldap.SCOPE_SUBTREE, user_filter, None)
        if res: # User found in LDAP Directory
            user_dn = res[0][0]
            user_information = res[0][1]
            ldap_session.simple_bind_s(user_dn, password) # <-- will throw  ldap.INVALID_CREDENTIALS if fails
            ldap_session.unbind_s()
            
            exact_username = user_information[askbot_settings.LDAP_USERID_FIELD][0]
            
            # Assuming last, first order
            # --> may be different
            last_name, first_name = user_information[askbot_settings.LDAP_COMMONNAME_FIELD][0].rsplit(" ", 1)
            email = user_information[askbot_settings.LDAP_EMAIL_FIELD][0]
            try:
                user = User.objects.get(username__exact=exact_username)
                # always update user profile to synchronize with ldap server
                user.set_password(password)
                user.first_name = first_name
                user.last_name = last_name
                user.email = email
                user.save()
            except User.DoesNotExist:
                # create new user in local db
                user = User()
                user.username = exact_username
                user.set_password(password)
                user.first_name = first_name
                user.last_name = last_name
                user.email = email
                user.is_staff = False
                user.is_superuser = False
                user.is_active = True
                user.save()

                log.info('Created New User : [{0}]'.format(exact_username))
            return user
        else:
            # Maybe a user created internally (django admin user)
            try:
                user = User.objects.get(username__exact=username)
                if user.check_password(password):
                    return user
                else:
                    return None
            except User.DoesNotExist:
                return None 

    except ldap.INVALID_CREDENTIALS, e:
        return None # Will fail login on return of None
    except ldap.LDAPError, e:
        log.error("LDAPError Exception")
        log.exception(e)
        return None
    except Exception, e:
        log.error("Unexpected Exception Occurred")
        log.exception(e)
        return None


class AuthBackend(object):
    """Authenticator's authentication backend class
    for more info, see django doc page:
    http://docs.djangoproject.com/en/dev/topics/auth/#writing-an-authentication-backend

    the reason there is only one class - for simplicity of
    adding this application to a django project - users only need
    to extend the AUTHENTICATION_BACKENDS with a single line

    todo: it is not good to have one giant do all 'authenticate' function
    """

    def authenticate(
                self,
                username = None,#for 'password' and 'ldap'
                password = None,#for 'password' and 'ldap'
                user_id = None,#for 'force'
                provider_name = None,#required with all except email_key
                openid_url = None,
                email_key = None,
                email = None, # used with mozilla-persona method
                oauth_user_id = None,#used with oauth
                facebook_user_id = None,#user with facebook
                wordpress_url = None, # required for self hosted wordpress
                wp_user_id = None, # required for self hosted wordpress
                method = None,#requried parameter
            ):
        """this authentication function supports many login methods
        just which method it is going to use it determined
        from the signature of the function call
        """
        login_providers = util.get_enabled_login_providers()
        assoc = None # UserAssociation not needed for ldap
        if method == 'password':
            if login_providers[provider_name]['type'] != 'password':
                raise ImproperlyConfigured('login provider must use password')
            if provider_name == 'local':
                try:
                    user = User.objects.get(username=username)
                    if not user.check_password(password):
                        return None
                except User.DoesNotExist:
                    try:
                        email_address = username
                        user = User.objects.get(email = email_address)
                        if not user.check_password(password):
                            return None
                    except User.DoesNotExist:
                        return None
                    except User.MultipleObjectsReturned:
                        LOG.critical(
                            ('have more than one user with email %s ' +
                            'he/she will not be able to authenticate with ' +
                            'the email address in the place of user name') % email_address
                        )
                        return None
            else:
                if login_providers[provider_name]['check_password'](username, password):
                    try:
                        #if have user associated with this username and provider,
                        #return the user
                        assoc = UserAssociation.objects.get(
                                        openid_url = username + '@' + provider_name,#a hack - par name is bad
                                        provider_name = provider_name
                                    )
                        return assoc.user
                    except UserAssociation.DoesNotExist:
                        #race condition here a user with this name may exist
                        user, created = User.objects.get_or_create(username = username)
                        if created:
                            user.set_password(password)
                            user.save()
                            user_registered.send(None, user = user)
                        else:
                            #have username collision - so make up a more unique user name
                            #bug: - if user already exists with the new username - we are in trouble
                            new_username = '%s@%s' % (username, provider_name)
                            user = User.objects.create_user(new_username, '', password)
                            user_registered.send(None, user = user)
                            message = _(
                                'Welcome! Please set email address (important!) in your '
                                'profile and adjust screen name, if necessary.'
                            )
                            user.message_set.create(message = message)
                else:
                    return None

            #this is a catch - make login token a little more unique
            #for the cases when passwords are the same for two users
            #from the same provider
            try:
                assoc = UserAssociation.objects.get(
                                            user = user,
                                            provider_name = provider_name
                                        )
            except UserAssociation.DoesNotExist:
                assoc = UserAssociation(
                                    user = user,
                                    provider_name = provider_name
                                )
            assoc.openid_url = username + '@' + provider_name#has to be this way for external pw logins

        elif method == 'openid':
            try:
                assoc = UserAssociation.objects.get(openid_url=openid_url)
                user = assoc.user
            except UserAssociation.DoesNotExist:
                return None
            except UserAssociation.MultipleObjectsReturned:
                logging.critical(
                    'duplicate openid url in the database!!! %s' % openid_url
                )
                return None

        elif method == 'mozilla-persona':
            try:
                assoc = UserAssociation.objects.get(
                                        openid_url=email,
                                        provider_name='mozilla-persona'
                                    )
                return assoc.user
            except UserAssociation.DoesNotExist:
                return None
            except UserAssociation.MultipleObjectsReturned:
                logging.critical(
                    'duplicate user with mozilla persona %s!!!' % email
                )

        elif method == 'email':
            #with this method we do no use user association
            try:
                #todo: add email_key_timestamp field
                #and check key age
                user = User.objects.get(email_key = email_key)
                user.email_key = None #one time key so delete it
                user.email_isvalid = True
                user.save()
                return user
            except User.DoesNotExist:
                return None

        elif method == 'valid_email':
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return None
            except User.MultipleObjectsReturned:
                LOG.critical(
                    ('have more than one user with email %s ' +
                    'he/she will not be able to authenticate with ' +
                    'the email address in the place of user name') % email_address
                )
                return None

            if user.email_isvalid == False:
                return None

            return user

        elif method == 'oauth':
            if login_providers[provider_name]['type'] in ('oauth', 'oauth2'):
                try:
                    assoc = UserAssociation.objects.get(
                                                openid_url = oauth_user_id,
                                                provider_name = provider_name
                                            )
                    user = assoc.user
                except UserAssociation.DoesNotExist:
                    return None
            else:
                return None

        elif method == 'facebook':
            try:
                #assert(provider_name == 'facebook')
                assoc = UserAssociation.objects.get(
                                            openid_url = facebook_user_id,
                                            provider_name = 'facebook'
                                        )
                user = assoc.user
            except UserAssociation.DoesNotExist:
                return None

        elif method == 'ldap':
            user = ldap_expedia_authenticate(username, password)

        elif method == 'wordpress_site':
            try:
                custom_wp_openid_url = '%s?user_id=%s' % (wordpress_url, wp_user_id)
                assoc = UserAssociation.objects.get(
                                            openid_url = custom_wp_openid_url,
                                            provider_name = 'wordpress_site'
                                            )
                user = assoc.user
            except UserAssociation.DoesNotExist:
                return None
        elif method == 'force':
            return self.get_user(user_id)
        else:
            raise TypeError('only openid and password supported')

        if assoc:
            #update last used time
            assoc.last_used_timestamp = datetime.datetime.now()
            assoc.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

    @classmethod
    def set_password(cls, 
                    user=None,
                    password=None,
                    provider_name=None
                ):
        """generic method to change password of
        any for any login provider that uses password
        and allows the password change function
        """
        login_providers = util.get_enabled_login_providers()
        if login_providers[provider_name]['type'] != 'password':
            raise ImproperlyConfigured('login provider must use password')

        if provider_name == 'local':
            user.set_password(password)
            user.save()
            scrambled_password = user.password + str(user.id)
        else:
            raise NotImplementedError('external passwords not supported')

        try:
            assoc = UserAssociation.objects.get(
                                        user = user,
                                        provider_name = provider_name
                                    )
        except UserAssociation.DoesNotExist:
            assoc = UserAssociation(
                        user = user,
                        provider_name = provider_name
                    )

        assoc.openid_url = scrambled_password
        assoc.last_used_timestamp = datetime.datetime.now()
        assoc.save()
