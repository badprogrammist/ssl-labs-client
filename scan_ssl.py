# coding=utf-8
"""
Скрипт анализирует SSL сайта и его поддоменов используя API SSL Labs (https://www.ssllabs.com/ssltest/index.html)

Требования
- Python 2.7

Запуск сприпта
python scan_ssl.py https://host1.com https://host2.com https://host3.com
"""

import datetime
import json
import os
import sys
import threading
import time
import urllib2
from Queue import Queue

# сколько секунд скрипт будет ждать результат по одному хосту
FETCHING_RESULT_TIMEOUT_IN_SECONDS = 20 * 60

# через сколько секунд делать попытку получить результат
TIME_BETWEEN_FETCH_RESULT_POLLING_IN_SECONDS = 10

# через сколько секунд начинать анализировать новый хост
TIME_BETWEEN_START_ANALYZE_NEW_HOST_IN_SECONDS = 10

# через сколько секунд делать новую попытку запустить анализ
# (если ssl lab недоступен или была ошибка)
TIME_BETWEEN_ANALYZE_POLLING_IN_SECONDS = 30

# максимальное кол-во попыток запустить анализ по одному хосту
MAX_ANALYZE_ATTEMPTS = 5

ANALYZE_URL = 'https://api.ssllabs.com/api/v3/analyze'
DEFAULT_ANALYZE_PARAMS = {
    'startNew': 'on',
    'all': 'done'
}
DEFAULT_FETCH_RESULT_PARAMS = {
    'all': 'done'
}

SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK', None)


def log(text):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print now + ' - ' + text


def _gen_args(params):
    args = ''

    if params:
        args = '?'
        first = True

        for key, value in params.iteritems():
            if not first:
                args += '&'
            else:
                first = False
            args += '{}={}'.format(key, value)

    return args


def _prepare_response(response):
    data = {'code': response.code}

    try:
        data.update(json.loads(response.read()))
    except ValueError:
        pass

    return data


def get(url, params=None):
    args = _gen_args(params)

    req = urllib2.Request(url + args)
    response = urllib2.urlopen(req)

    return _prepare_response(response)


def post(url, body):
    req = urllib2.Request(url)
    req.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(req, json.dumps(body))

    return _prepare_response(response)


class Result(object):
    def __init__(self, host):
        self.host = host
        self.data = None
        self.expire = False
        self.server_unavailable = False

    def ready(self):
        if self.data is not None:
            status = self.data['status']

            if status == 'READY' or status == 'ERROR':
                return True

        if self.expire:
            return True

        return False


class Analyzer(threading.Thread):
    def __init__(self, index, host, results_queue):
        super(Analyzer, self).__init__()
        self.index = index
        self.host = host
        self.result = Result(host)
        self._start_time = None
        self._results_queue = results_queue
        self._attempts = MAX_ANALYZE_ATTEMPTS

    def run(self):
        if self.index != 0:
            time.sleep(
                self.index * TIME_BETWEEN_START_ANALYZE_NEW_HOST_IN_SECONDS)

        analyze_success = self._analyze()

        if not analyze_success:
            self.result.server_unavailable = True
        else:
            self._fetch_result()

        self._results_queue.put(self.result)

    def _analyze(self):
        analyze_success = self._do_analyze()

        while not analyze_success and self._attempts > 0:
            time.sleep(TIME_BETWEEN_ANALYZE_POLLING_IN_SECONDS)
            self._attempts -= 1
            log('New attempt of analyzing {}...'.format(self.host))
            analyze_success = self._do_analyze()

        return analyze_success

    def _do_analyze(self):
        log('Start analyzing {}...'.format(self.host))
        params = DEFAULT_ANALYZE_PARAMS.copy()
        params['host'] = self.host

        try:
            response = get(ANALYZE_URL, params)
        except urllib2.HTTPError as ex:
            log('An error "{}" during start analyze {}'.format(str(ex),
                                                               self.host))
            return False

        if response['code'] != 200:
            log('Fail analyzing {}...'.format(self.host))
            return False

        return True

    def _fetch_result(self):
        self._start_time = datetime.datetime.now()

        while not self.result.ready():
            time.sleep(TIME_BETWEEN_FETCH_RESULT_POLLING_IN_SECONDS)
            self._do_fetch_result()
            self._timeout_expire()

    def _do_fetch_result(self):
        log('Trying to fetch result on {}...'.format(self.host))
        params = DEFAULT_FETCH_RESULT_PARAMS.copy()
        params['host'] = self.host

        try:
            self.result.data = get(ANALYZE_URL, params)
        except urllib2.HTTPError as ex:
            log('An error "{}" during fetch result on {}'.format(str(ex),
                                                                 self.host))

    def _timeout_expire(self):
        if not self.result.ready():
            now = datetime.datetime.now()
            last_seconds = (now - self._start_time).total_seconds()

            if last_seconds > FETCHING_RESULT_TIMEOUT_IN_SECONDS:
                self.result.expire = True
                log('The result from {} was not got at last.'.format(self.host))


class SlackReporter(threading.Thread):
    def __init__(self, results_queue, amount):
        super(SlackReporter, self).__init__()
        self._results_queue = results_queue
        self._running = False
        self.amount = amount

    def start(self):
        self._running = True
        super(SlackReporter, self).start()

    def run(self):
        while self._running:
            result = self._results_queue.get()
            self.report(result)
            self._task_done()

    def report(self, result):
        message = self._gen_message(result)

        log('{} - {}'.format(result.host, json.dumps(message)))

        try:
            if SLACK_WEBHOOK is None or SLACK_WEBHOOK == '':
                log('Could not send report to Slack. Env variable SLACK_WEBHOOK is absence')
            else:
                post(SLACK_WEBHOOK, message)
        except urllib2.HTTPError as ex:
            log('An error "{}" during sending result to Slack'.format(str(ex)))

    @staticmethod
    def _gen_message(result):
        attachments = []

        ssl_lab_host_link = SlackReporter._ssl_labs_link(result.data['host'])

        if result.expire:
            attachment = SlackReporter._attachment(color='danger',
                                                   link=ssl_lab_host_link,
                                                   text='The result was not got at last')
            attachments.append(attachment)

        elif result.server_unavailable:
            attachment = SlackReporter._attachment(color='danger',
                                                   link=ssl_lab_host_link,
                                                   text='The server of SSL Lab was not available')
            attachments.append(attachment)

        elif result.data['status'] == 'ERROR':
            attachment = SlackReporter._attachment(color='danger',
                                                   link=ssl_lab_host_link,
                                                   text=result.data['statusMessage'])
            attachments.append(attachment)

        else:
            for endpoint in result.data['endpoints']:
                rating = None
                color = None
                text = ''
                title = endpoint['ipAddress']

                if 'grade' in endpoint:
                    rating = endpoint['grade']
                    color = SlackReporter._color(rating)
                else:
                    color = 'danger'
                    text = endpoint['statusMessage']

                link = SlackReporter._ssl_labs_sd_link(result.data['host'],
                                                       endpoint['ipAddress'])

                attachment = SlackReporter._attachment(color=color,
                                                       title=title,
                                                       link=link,
                                                       rating=rating,
                                                       text=text)
                attachments.append(attachment)

        message = {
            'text': result.data['host'],
            'username': 'ssl-labs',
            'icon_emoji': ':shield:',
            'attachments': attachments
        }

        return message

    @staticmethod
    def _color(rating):
        if rating in ['A+', 'A-', 'A']:
            return 'good'

        elif rating in ['B', 'C', 'D', 'E']:
            return 'warning'

        elif rating in ['F', 'T', 'M']:
            return 'danger'
        else:
            return ''

    @staticmethod
    def _ssl_labs_link(host):
        return 'https://www.ssllabs.com/ssltest/analyze.html?d={}'.format(host)

    @staticmethod
    def _ssl_labs_sd_link(host, ip):
        return 'https://www.ssllabs.com/ssltest/analyze.html?d={}&s={}'.format(host, ip)

    @staticmethod
    def _attachment(**kwargs):
        data = {
            "color": kwargs.get('color', ''),
            "title": kwargs.get('title', ''),
            "title_link": kwargs.get('link', ''),
            "text": kwargs.get('text', '')
        }

        if 'rating' in kwargs \
                and kwargs['rating'] is not None \
                and kwargs['rating'] != '':
            data['fields'] = [
                {
                    "title": "Rating",
                    "value": kwargs['rating'],
                    "short": True
                }
            ]

        return data

    def stop(self):
        self._running = False

    def _task_done(self):
        self._results_queue.task_done()
        self.amount -= 1

        if self.amount <= 0:
            self.stop()


def get_hosts():
    return sys.argv[1:]


def scan_hosts(hosts):
    results_queue = Queue()
    reporter = SlackReporter(results_queue, len(hosts))

    reporter.start()

    for idx, host in enumerate(hosts):
        analyzer = Analyzer(idx, host, results_queue)
        analyzer.start()

    results_queue.join()


if __name__ == '__main__':
    hosts = get_hosts()

    if len(hosts) > 0:
        scan_hosts(hosts)
