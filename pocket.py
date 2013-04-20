#!/usr/bin/python2

from datetime import datetime
import time
import requests
import json

API_BASE = 'https://getpocket.com/v3/'
AUTH_BASE = 'https://getpocket.com/auth/authorize'


class APIException(Exception):
    def __init__(self, request):
        self.request = request
        self.status_code = request.status_code
        self.reason = request.reason
        self.headers = request.headers

    def __str__(self):
        return '{}: {}'.format(
            self.status_code,
            self.headers.get('x-error', self.reason)
        )


class API(object):
    def __init__(self, consumer_key, redirect_uri='local:callback'):
        self.consumer_key = consumer_key
        self.redirect_uri = redirect_uri
        self.reset()

    def reset(self):
        self._last = self._login = self._request_token = None
        self._actions = []
        self.limits = {}

    def login(self, username=None, access_token=None):
        if self._login:
            pass
        elif username and access_token:
            self._login = {'username': username, 'access_token': access_token}
        else:
            self._login = self.post('oauth/authorize', code=self.request_token)

        return self._login

    @property
    def authenticated(self):
        return bool(self._login)

    def post(self, endpoint, **params):
        headers = {'X-Accept': 'application/json'}

        params['consumer_key'] = self.consumer_key
        if self.authenticated and 'oauth' not in endpoint:
            params['access_token'] = self.access_token

        res = requests.post(API_BASE + endpoint, params, headers=headers)

        self._last = res
        for k, v in res.headers.items():
            k = k.lower()
            if k.startswith('x-limit'):
                self.limits[k] = int(v)

        if not res.ok:
            raise APIException(res)

        return res.json()

    @property
    def request_token(self):
        if self._request_token:
            return self._request_token

        res = self.post('oauth/request', redirect_uri=self.redirect_uri)

        self._request_token = res['code']
        return self._request_token

    @property
    def auth_url(self):
        return AUTH_BASE + '?request_token={}&redirect_uri={}'.format(
            self.request_token, self.redirect_uri)

    @property
    def access_token(self):
        if not self._login:
            self.login()
        return self._login['access_token']

    @property
    def username(self):
        if not self._login:
            self.login()
        return self._login['username']

    @property
    def remaining_calls(self):
        limits = [v for k, v in self.limits.items()
                  if k.endswith('remaining')]
        if limits:
            return min(limits)

    @property
    def seconds_until_reset(self):
        limits = [v for k, v in self.limits.items()
                  if k.endswith('reset')]
        if limits:
            return max(limits)

    def get(self, **params):
        """Retrieve items from a user's Pocket list.

        :param state: Get only read or unread items. Defaults to unread.
        :type state: 'unread', 'archive', 'all'
        :param favorite: Only return favorited items.
        :type favorite: bool
        :param tag: Only return items with a certain tag.
        :type tag: str or '_untagged_'
        :param contentType: Only return items with a certain content type.
        :type contentType: 'article', 'video' or 'image'
        :param sort: Return items in a certain order.
        :type sort: 'newest', 'oldest', 'title' or 'site'
        :param detailType: Only return the titles and urls of each item
            or return all data about each item.
        :type detailType: 'simple' or 'complete'
        :param search: Only return items whose title or url contain
            the search string.
        :type search: str
        :param since: Only return items modified since the given
            unix timestamp.
        :type since: int
        :param count: Number of items to retrieve.
        :type count: int
        :param offset: Used only with count; start returning from offset
            position of results.
        :type offset: int

        :returns: Response from server containing the keys
            'status', 'list', 'complete' and 'since'.
        :rtype: dictionary
        :raises: See :meth:`post`.
        """

        if 'since' in params and isinstance(params['since'], datetime):
            params['since'] = time.mktime(params['since'].timetuple())

        if 'favorite' in params:
            params['favorite'] = int(bool(params['favorite']))

        return self._cleanup_json(self.post('get', **params))

    @classmethod
    def _cleanup_json(cls, json):
        for k, v in json.items():
            try:
                v = int(v)
            except (ValueError, TypeError):
                pass

            if k.startswith('time_') or k in ['since']:
                v = datetime.fromtimestamp(v) if v else None
            if isinstance(v, dict):
                v = cls._cleanup_json(v)

            json[k] = v

        return json

    def send(self):
        """Send all queued actions to the server.

        :returns: Response from server containing the keys
            'status' and 'action_results'.
        :rtype: dictionary
        :raises: See :meth:`post`.
        """
        if not self._actions:
            return

        res = self.post('send', actions=json.dumps(self._actions))

        # post did not throw an error, return results merged into queue.
        actions = self._actions
        self._actions = []

        results = res.pop('action_results', [False for a in self._actions])
        for action, result in zip(actions, results):
            action['result'] = result
        res['actions'] = actions

        return res

    def queue(self, action, **params):
        """Add a new action to the queue. Use :meth:`send` to send the
        changes to the server.

        :param action: Name or type of action.
        :type action: str
        :param params: Parameters for the action.
        """

        params['action'] = action

        if 'time' in params and isinstance(params['time'], datetime):
            params['time'] = time.mktime(params['time'].timetuple())

        self._actions.append(params)

    def add(self, url, **params):
        """Add a new item to the user's list.

        :param url: The url of the item.
        :type url: str
        :param tags: A list of one or more tags. (optional)
        :type tags: list or coma-separated str
        :param time: The time the action occurred. (optional)
        :type time: int
        :param title: The title of the item. (optional)
        :type title: str
        """

        if 'tags' in params and isinstance(params['tags'], basestring):
            params['tags'] = params['tags'].split(',')

        self.queue('add', url=url, **params)

    def archive(self, item_id, **params):
        """Move an item to the user's archive.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        self.queue('archive', item_id=item_id, **params)

    def readd(self, item_id, **params):
        """Move an item from the user's archive back into their unread list.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        self.queue('readd', item_id=item_id, **params)

    def favorite(self, item_id, **params):
        """Mark an item as a favorite.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        self.queue('favorite', item_id=item_id, **params)

    def unfavorite(self, item_id, **params):
        """Remove an item from the user's favorites.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        self.queue('unfavorite', item_id=item_id, **params)

    def delete(self, item_id, **params):
        """Permanently remove an item from the user's account.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        self.queue('delete', item_id=item_id, **params)

    def tags_add(self, item_id, tags, **params):
        """Add one or more tags to an item.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param tags: A list of one or more tags.
        :type tags: list or coma-separated str
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        if isinstance(tags, basestring):
            tags = tags.split(',')

        self.queue('tags_add', item_id=item_id, tags=tags, **params)

    def tags_remove(self, item_id, tags, **params):
        """Remove one or more tags from an item.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param tags: A list of one or more tags.
        :type tags: list or coma-separated str
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        if isinstance(tags, basestring):
            tags = tags.split(',')

        self.queue('tags_remove', item_id=item_id, tags=tags, **params)

    def tags_replace(self, item_id, tags, **params):
        """Replace all of the tags for an item with the one or more
        provided tags.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param tags: A list of one or more tags.
        :type tags: list or coma-separated str
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        if isinstance(tags, basestring):
            tags = tags.split(',')

        self.queue('tags_replace', item_id=item_id, tags=tags, **params)

    def tags_clear(self, item_id, **params):
        """Remove all tags from an item.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param time: The time the action occurred. (optional)
        :type time: int
        """

        self.queue('tags_clear', item_id=item_id, **params)

    def tag_rename(self, item_id, old_tag, new_tag, **params):
        """Rename a tag. This affects all items with this tag.

        :param item_id: The id of the item to perform the action on.
        :type item_id: int
        :param old_tag: The tag name that will be replaced.
        :type old_tag: str
        :param new_tag: The new tag name that will be added.
        :type new_tag: str
        """

        self.queue('tag_rename', item_id=item_id,
                   old_tag=old_tag, new_tag=new_tag, **params)
