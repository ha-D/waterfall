import threading
import logging
from Queue import Queue

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import Proxy
from selenium.common.exceptions import TimeoutException


log = logging.getLogger(__name__)


class BaseDriver(object):
    browser = None

    def __init__(self, config=None):
        self.driver = None
        self.config = config or {}
        self.alive = False

        self.ready_condition = threading.Condition()
        self.task_queue = Queue()

        # turn of logging
        selenium_logger = logging.getLogger('selenium.webdriver.remote.remote_connection')
        selenium_logger.setLevel(logging.WARNING)

    def _initialize_driver(self, driver, config):
        # config.setdefault('window_size', {'width': 1200, 'height': 800})
        # driver.set_window_size(config['window_size']['width'], config['window_size']['height'])

        if not config.setdefault('cookies', False):
            driver.delete_all_cookies()

        self.initialize_driver(driver, config)

    def create_driver(self, config):
        pass

    def initialize_driver(self, driver, config):
        pass

    def wait_until_ready(self):
        with self.ready_condition:
            self.ready_condition.wait()

    def start(self, wait=False):
        t = threading.Thread(target=self._start)
        t.daemon = True
        t.start()

        if wait:
            self.wait_until_ready()

    def _start(self):
        self.driver = self.create_driver(self.config)
        self._initialize_driver(self.driver, self.config)
        log.info("Browser initialized")

        with self.ready_condition:
            self.ready_condition.notifyAll()

        self.alive = True
        while self.alive:
            task = self.task_queue.get()
            self.get(task)

    def get(self, url):
        try:
            # self.driver.set_page_load_timeout(50)
            self.driver.get(url)
        except TimeoutException:
            pass

    def queue_url(self, url):
        self.task_queue.put_nowait(url)

    def close(self):
        self.driver.close()

    def stop(self):
        self.driver.stop_client()

    def pid(self):
        import psutil
        gecko_pid = self.driver.service.process.pid
        return psutil.Process(gecko_pid).children()[0].pid

    def quit(self):
        self.alive = False
        self.driver.quit()


class FirefoxDriver(BaseDriver):
    browser = 'Firefox'

    def create_driver(self, config):
        profile = webdriver.FirefoxProfile()
        self.init_profile(profile, config)

        return webdriver.Firefox(firefox_profile=profile)

    def initialize_driver(self, driver, config):
        pass

    def init_profile(self, profile, config):

        # Turn off cache
        if not config.get('cache', True):
            profile.set_preference('browser.download.folderList', 2)
            profile.set_preference("browser.cache.disk.enable", False)
            profile.set_preference("browser.cache.memory.enable", False)
            profile.set_preference("browser.cache.offline.enable", False)
            profile.set_preference("network.http.use-cache", False)

            # Disable DNS cache
            profile.set_preference('network.dnsCacheExpiration', 0)

        # Set proxy
        if 'proxy' in config:
            profile.set_preference('network.proxy.type', 1)
            if 'ssl' in config['proxy']:
                profile.set_preference('network.proxy.ssl', config['proxy']['ssl']['host'])
                profile.set_preference('network.proxy.ssl_port', config['proxy']['ssl']['port'])

        if not config.get('verify_certs', True):
            profile.accept_untrusted_certs = True


class PhantomDriver(BaseDriver):
    browser = 'PhantomJS'

    def create_driver(self, config):
        service_args = []
        if 'proxy' in config:
            if 'ssl' in config['proxy']:
                service_args.append('--proxy={}:{}'.format(config['proxy']['ssl']['host'], config['proxy']['ssl']['port']))
                service_args.append('--proxy-type=https')

        if not config.get('verify_certs', True):
            service_args.append('--ignore-ssl-errors=true')

        if not config.get('cache', True):
            # !! No way to disable memory cache

            service_args.append('--disk-cache=false')

        return webdriver.PhantomJS(service_args=service_args)

