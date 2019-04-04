import hashlib
import logging
import time

from assemblyline.common.exceptions import RecoverableError
from assemblyline.common.isotime import iso_to_local, iso_to_epoch, epoch_to_local, now, now_as_local
from assemblyline.al.common.result import Result, ResultSection, Classification, SCORE
from assemblyline.al.common.av_result import VirusHitTag
from assemblyline.al.service.base import ServiceBase

log = logging.getLogger("assemblyline.svc.common.result")


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name, engine, score):
        title = '{} identified the file as {}'.format(av_name, virus_name)
        body = ""
        if engine:
            body = "Engine: {} :: Definition: {}".format(engine['version'], engine['def_time'])
        super(AvHitSection, self).__init__(
            title_text=title,
            score=score,
            body=body,
            classification=Classification.UNRESTRICTED
        )


class AvErrorSection(ResultSection):
    def __init__(self, av_name, engine, score):
        title = '{} failed to scan the file'.format(av_name)
        body = ""
        if engine:
            body = "Engine: {} :: Definition: {}".format(engine['version'], engine['def_time'])
        super(AvErrorSection, self).__init__(
            title_text=title,
            score=score,
            body=body,
            classification=Classification.UNRESTRICTED
        )


class MetaDefender(ServiceBase):
    SERVICE_CATEGORY = "Antivirus"
    SERVICE_DESCRIPTION = "This service is a multi scanner with 20 engines."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_STAGE = 'CORE'
    SERVICE_CPU_CORES = 0.1
    SERVICE_RAM_MB = 64
    SERVICE_DEFAULT_CONFIG = {
        'BASE_URL': 'http://localhost:8008/',
        "MD_VERSION": 4,
        'MD_TIMEOUT': 40,
        'MIN_NODE_TIME': 60,
        'MAX_NODE_TIME': 300,
        'MAX_MD_SCAN_TIME': 5
    }

    def __init__(self, cfg=None):
        super(MetaDefender, self).__init__(cfg)
        self.session = None
        self._updater_id = "ENABLE_SERVICE_BLK_MSG"
        self.timeout = cfg.get('MD_TIMEOUT', (self.SERVICE_TIMEOUT*2)/3)
        self.nodes = {}
        self.current_node = None
        self.start_time = None

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global requests, random
        import requests
        import random

    def start(self):
        self.log.debug("MetaDefender service started")
        base_urls = []
        if type(self.cfg.get('BASE_URL')) == str:
            base_urls = [self.cfg.get('BASE_URL')]
        elif type(self.cfg.get('BASE_URL')) == list:
            for base_url in self.cfg.get('BASE_URL'):
                base_urls.append(base_url)
        else:
            raise Exception("Invalid format for BASE_URL service variable")

        # Initialize a list of all nodes with default data
        for index, url in enumerate(base_urls):
            self.nodes[url] = {'engine_map': {},
                               'engine_count': 0,
                               'engine_list': "default",
                               'newest_dat': epoch_to_local(0),
                               'oldest_dat': now_as_local(),
                               'file_count': 0,
                               'queue_times': [],
                               'average_queue_time': 0
                               }

        # Get version map for all of the nodes
        self.session = requests.Session()
        engine_count = 0
        for node in self.nodes.keys():
            self._get_version_map(node)
            engine_count += self.nodes[node]['engine_count']

        if engine_count == 0:
            raise Exception("Unable to reach any MetaDefender node to get version map")

        # On first launch, choose random node to start with
        if not self.current_node:
            while True:
                self.current_node = random.choice(list(self.nodes.keys()))

                # Check to see if the chosen node has a version map, else try to get version map again
                if self.nodes[self.current_node]['engine_count'] >= 1:
                    self.log.info("MetaDefender node: {}, chosen at launch".format(self.current_node))
                    break
                else:
                    self._get_version_map(self.current_node)

        # Start the global timer
        if not self.start_time:
            self.start_time = time.time()

    @staticmethod
    def _format_engine_name(name):
        new_name = name.lower().replace(" ", "").replace("!", "")
        if new_name.endswith("av"):
            new_name = new_name[:-2]
        return new_name

    def _get_version_map(self, node):
        newest_dat = 0
        oldest_dat = now()
        engine_list = []
        url = node + 'stat/engines'

        try:
            r = self.session.get(url=url, timeout=self.timeout)
            engines = r.json()

            for engine in engines:
                if self.cfg.get("MD_VERSION") == 4:
                    name = self._format_engine_name(engine["eng_name"])
                    version = engine['eng_ver']
                    def_time = engine['def_time']
                    etype = engine['engine_type']
                elif self.cfg.get("MD_VERSION") == 3:
                    name = self._format_engine_name(engine["eng_name"]).replace("scanengine", "")
                    version = engine['eng_ver']
                    def_time = engine['def_time'].replace(" AM", "").replace(" PM", "").replace("/", "-").replace(" ",
                                                                                                                  "T")
                    def_time = def_time[6:10] + "-" + def_time[:5] + def_time[10:] + "Z"
                    etype = engine['eng_type']
                else:
                    raise Exception("Unknown MetaDefender version")

                # Compute newest DAT
                dat_epoch = iso_to_epoch(def_time)
                if dat_epoch > newest_dat:
                    newest_dat = dat_epoch

                if dat_epoch < oldest_dat and dat_epoch != 0 and etype in ["av", "Bundled engine"]:
                    oldest_dat = dat_epoch

                self.nodes[node]['engine_map'][name] = {
                    'version': version,
                    'def_time': iso_to_local(def_time)[:19]
                }
                engine_list.append(name)
                engine_list.append(version)
                engine_list.append(def_time)

            self.nodes[node]['engine_count'] = len(engines)
            self.nodes[node]['newest_dat'] = epoch_to_local(newest_dat)[:19]
            self.nodes[node]['oldest_dat'] = epoch_to_local(oldest_dat)[:19]
            self.nodes[node]['engine_list'] = "".join(engine_list)
        except requests.exceptions.Timeout:
            self.log.warning("MetaDefender node: {}, timed out after {}s while trying to get engine version map".format(
                node, self.timeout))
        except requests.ConnectionError:
            self.log.warning("Unable to connect to MetaDefender node: {}, while trying to get engine version map".format(node))

    def get_tool_version(self):
        engine_lists = ""
        for node in self.nodes.keys():
            engine_lists += self.nodes[node]['engine_list']
        return hashlib.md5(engine_lists).hexdigest()

    def execute(self, request):
        # Check that the current node has a version map
        while True:
            if self.nodes[self.current_node]['engine_count'] == 0:
                self._get_version_map(self.current_node)
                self.log.info("Getting version map from execute() function")
                if self.nodes[self.current_node]['engine_count'] == 0:
                    self.new_node(force=True)
            else:
                break

        filename = request.download()
        try:
            response = self.scan_file(filename)
        except RecoverableError:
            response = self.scan_file(filename)
        result = self.parse_results(response)
        request.result = result
        request.set_service_context(
            "Definition Time Range: {} - {}".format(self.nodes[self.current_node]['oldest_dat'],
                                                    self.nodes[self.current_node]['newest_dat']))

        # Compare queue time of current node with new random node after a minimum run time on current node
        elapsed_time = self.start_time - time.time()
        if elapsed_time >= self.cfg.get('MAX_NODE_TIME'):
            self.new_node(force=True)
        elif elapsed_time >= self.cfg.get('MIN_NODE_TIME'):
            self.new_node(force=False)

    def get_scan_results_by_data_id(self, data_id):
        url = self.current_node + 'file/{0}'.format(data_id)

        try:
            return self.session.get(url=url, timeout=self.timeout)
        except requests.exceptions.Timeout:
            self.new_node(force=True)
            raise Exception("MetaDefender node: {}, timed out after {}s while trying to fetch scan results".format(
                self.current_node, self.timeout))

        except requests.ConnectionError:
            # MetaDefender inaccessible
            self.new_node(force=True)
            raise RecoverableError("Unable to reach MetaDefender node: {}, while trying to fetch scan results".format(
                self.current_node))

    def new_node(self, force):
        if len(self.nodes) == 1:
            time.sleep(5)
            return

        # Close the requests session before moving on to select new node
        self.session.close()

        if self.nodes[self.current_node]['file_count'] > 1:
            average = sum(self.nodes[self.current_node]['queue_times']) / self.nodes[self.current_node]['file_count']
            while True:
                temp_node = random.choice(list(self.nodes.keys()))
                if temp_node != self.current_node:
                    if force:
                        self.log.info("Changed MetaDefender node from: {}, to: {}".format(self.current_node, temp_node))
                        self.nodes[self.current_node]['average_queue_time'] = average
                        self.nodes[self.current_node]['file_count'] = 0
                        self.current_node = temp_node
                        self.start_time = time.time()
                        return
                    else:
                        # Only change to new node if the current node's average queue time is larger than the new node
                        if average > self.nodes[temp_node]['average_queue_time']:
                            self.log.info("Changed MetaDefender node from: {}, to: {}".format(self.current_node, temp_node))
                            self.nodes[self.current_node]['average_queue_time'] = average
                            self.nodes[self.current_node]['file_count'] = 0
                            self.current_node = temp_node

                        # Reset the start time
                        self.start_time = time.time()
                        return

    def scan_file(self, filename):
        # Let's scan the file
        url = self.current_node + 'file'
        with open(filename, 'rb') as f:
            data = f.read()

        try:
            r = self.session.post(url=url, data=data, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise Exception("MetaDefender node: {}, timed out after {}s while trying to send file for scanning".format(self.current_node, self.timeout))
        except requests.ConnectionError:
            # MetaDefender inaccessible
            self.new_node(force=True)  # Deactivate the current node which had a connection error
            raise RecoverableError(
                "Unable to reach MetaDefender node: {}, while trying to send file for scanning".format(
                    self.current_node))

        if r.status_code == requests.codes.ok:
            data_id = r.json()['data_id']
            while True:
                r = self.get_scan_results_by_data_id(data_id=data_id)
                if r.status_code != requests.codes.ok:
                    return r.json()
                try:
                    if r.json()['scan_results']['progress_percentage'] == 100:
                        break
                    else:
                        time.sleep(0.5)
                except KeyError:
                    # MetaDefender inaccessible
                    self.new_node(force=True)
                    raise RecoverableError(
                        "Unable to reach MetaDefender node: {}, while trying to fetch scan results".format(
                            self.current_node))

            self.nodes[self.current_node]['timeout_count'] = 0
            self.nodes[self.current_node]['timeout'] = 0

        return r.json()

    def parse_results(self, response):
        res = Result()
        scan_results = response.get('scan_results', response)
        virus_name = ""

        if scan_results is not None and scan_results.get('progress_percentage') == 100:
            hit = False
            av_hits = ResultSection(title_text='Anti-Virus Detections')

            scans = scan_results.get('scan_details', scan_results)
            av_scan_times = []
            for majorkey, subdict in sorted(scans.iteritems()):
                score = SCORE.NULL
                if subdict['scan_result_i'] == 1:           # File is infected
                    virus_name = subdict['threat_found']
                    if virus_name:
                        score = SCORE.SURE
                elif subdict['scan_result_i'] == 2:         # File is suspicious
                    virus_name = subdict['threat_found']
                    if virus_name:
                        score = SCORE.VHIGH
                elif subdict['scan_result_i'] == 10 or subdict['scan_result_i'] == 3:   # File was not scanned or failed
                    try:
                        engine = self.nodes[self.current_node]['engine_map'][self._format_engine_name(majorkey)]
                    except:
                        engine = None
                    av_hits.add_section(AvErrorSection(majorkey, engine, score))
                    hit = True

                if score:
                    virus_name = virus_name.replace("a variant of ", "")
                    engine = self.nodes[self.current_node]['engine_map'][self._format_engine_name(majorkey)]
                    res.append_tag(VirusHitTag(virus_name, context="scanner:{}".format(majorkey)))
                    av_hits.add_section(AvHitSection(majorkey, virus_name, engine, score))
                    hit = True

                av_scan_times.append(self._format_engine_name(majorkey))
                av_scan_times.append(subdict['scan_time'])

            if hit:
                res.add_result(av_hits)

            file_size = response['file_info']['file_size']
            queue_time = response['process_info']['queue_time']
            processing_time = response['process_info']['processing_time']
            self.log.info(
                "File successfully scanned by MetaDefender node: {}. File size: {} B. Queue time: {} ms. Processing time: {} ms. AV scan times: {}".format(
                    self.current_node, file_size, queue_time, processing_time, str(av_scan_times)))

            # Add the queue time to a list, which will be later used to calculate average queue time
            self.nodes[self.current_node]['queue_times'].append(queue_time)
            self.nodes[self.current_node]['file_count'] += 1

        return res
