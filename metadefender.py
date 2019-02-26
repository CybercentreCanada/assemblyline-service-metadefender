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
        'MAX_MD_SCAN_TIME': 5
    }

    def __init__(self, cfg=None):
        super(MetaDefender, self).__init__(cfg)
        self.session = None
        self._updater_id = "ENABLE_SERVICE_BLK_MSG"
        self.timeout = cfg.get('MD_TIMEOUT', (self.SERVICE_TIMEOUT*2)/3)
        self.md_nodes = {}
        self.current_md_node = 0

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global requests
        import requests

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

        for index, url in enumerate(base_urls):
            self.md_nodes[index] = {'base_url': url,
                                    'timeout_count': 0,
                                    'timeout': 0,
                                    'engine_map': {},
                                    'engine_count': 0,
                                    'engine_list': "default",
                                    'newest_dat': epoch_to_local(0),
                                    'oldest_dat': now_as_local()
                                    }

        self.session = requests.session()
        engine_count = 0
        for i in range(len(self.md_nodes)):
            self._get_version_map(i)
            engine_count += self.md_nodes[i]['engine_count']

        if engine_count == 0:
            raise Exception("Unable to reach any MetaDefender node to get version map")

    @staticmethod
    def _format_engine_name(name):
        new_name = name.lower().replace(" ", "").replace("!", "")
        if new_name.endswith("av"):
            new_name = new_name[:-2]
        return new_name

    def _get_version_map(self, i):
        newest_dat = 0
        oldest_dat = now()
        engine_list = []
        url = self.md_nodes[i]['base_url'] + 'stat/engines'

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

                self.md_nodes[i]['engine_map'][name] = {
                    'version': version,
                    'def_time': iso_to_local(def_time)[:19]
                }
                engine_list.append(name)
                engine_list.append(version)
                engine_list.append(def_time)

            self.md_nodes[i]['engine_count'] = len(engines)
            self.md_nodes[i]['newest_dat'] = epoch_to_local(newest_dat)[:19]
            self.md_nodes[i]['oldest_dat'] = epoch_to_local(oldest_dat)[:19]
            self.md_nodes[i]['engine_list'] = "".join(engine_list)
        except requests.exceptions.Timeout:
            self.deactivate_node()
            self.log.warning("MetaDefender node: {}, timed out while trying to get engine version map".format(
                self.md_nodes[self.current_md_node]['base_url']))
        except requests.ConnectionError:
            self.deactivate_node()
            self.log.warning("Unable to connect to MetaDefender node: {}, while trying to get engine version map".format(
                    self.md_nodes[self.current_md_node]['base_url']))

    def get_tool_version(self):
        engine_lists = ""
        for i in range(len(self.md_nodes)):
            engine_lists += self.md_nodes[i]['engine_list']
        return hashlib.md5(engine_lists).hexdigest()

    def execute(self, request):
        if self.md_nodes[self.current_md_node]['engine_count'] == 0:
            self._get_version_map(self.current_md_node)
            self.log.info("Getting version map from execute() function")
            if self.md_nodes[self.current_md_node]['engine_count'] == 0:
                self.deactivate_node()

        filename = request.download()
        try:
            response = self.scan_file(filename)
        except RecoverableError:
            response = self.scan_file(filename)
        result = self.parse_results(response)
        request.result = result
        request.set_service_context(
            "Definition Time Range: {} - {}".format(self.md_nodes[self.current_md_node]['oldest_dat'],
                                                    self.md_nodes[self.current_md_node]['newest_dat']))
        self.next_node()

    def get_scan_results_by_data_id(self, data_id):
        url = self.md_nodes[self.current_md_node]['base_url'] + 'file/{0}'.format(data_id)

        try:
            return self.session.get(url=url, timeout=self.timeout)
        except requests.exceptions.Timeout:
            self.deactivate_node()
            raise Exception("MetaDefender node: {}, timed out while trying to fetch scan results".format(
                self.md_nodes[self.current_md_node]['base_url']))
        except requests.ConnectionError:
            # MetaDefender inaccessible
            if len(self.md_nodes) == 1:
                time.sleep(5)
            self.deactivate_node()
            raise RecoverableError("Unable to reach MetaDefender node: {}, while trying to fetch scan results".format(
                self.md_nodes[self.current_md_node]['base_url']))

    def deactivate_node(self):
        if len(self.md_nodes) > 1:
            if self.md_nodes[self.current_md_node]['timeout_count'] <= 4:
                self.md_nodes[self.current_md_node]['timeout_count'] += 1
                self.md_nodes[self.current_md_node]['timeout'] = self.md_nodes[self.current_md_node]['timeout_count']
            else:
                self.md_nodes[self.current_md_node]['timeout'] = 5

            self.next_node()

    def next_node(self):
        if len(self.md_nodes) == 1:
            return

        while True:
            if self.current_md_node == len(self.md_nodes) - 1:
                self.current_md_node = 0
            else:
                self.current_md_node += 1

            if self.md_nodes[self.current_md_node]['timeout'] == 0:
                break
            else:
                self.md_nodes[self.current_md_node]['timeout'] -= 1

    def scan_file(self, filename):
        # Let's scan the file
        url = self.md_nodes[self.current_md_node]['base_url'] + 'file'
        with open(filename, 'rb') as f:
            data = f.read()

        try:
            r = self.session.post(url=url, data=data, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise Exception("MetaDefender node: {}, timed out while trying to send file for scanning".format(
                self.md_nodes[self.current_md_node]['base_url']))
        except requests.ConnectionError:
            # MetaDefender inaccessible
            if len(self.md_nodes) == 1:
                time.sleep(5)
            self.deactivate_node()  # Deactivate the current node which had a connection error
            raise RecoverableError(
                "Unable to reach MetaDefender node: {}, while trying to send file for scanning".format(
                    self.md_nodes[self.current_md_node]['base_url']))

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
                    if len(self.md_nodes) == 1:
                        time.sleep(5)
                    self.deactivate_node()
                    raise RecoverableError(
                        "Unable to reach MetaDefender node: {}, while trying to fetch scan results".format(
                            self.md_nodes[self.current_md_node]['base_url']))

            self.md_nodes[self.current_md_node]['timeout_count'] = 0
            self.md_nodes[self.current_md_node]['timeout'] = 0

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
                        engine = self.md_nodes[self.current_md_node]['engine_map'][self._format_engine_name(majorkey)]
                    except:
                        engine = None
                    av_hits.add_section(AvErrorSection(majorkey, engine, score))
                    hit = True

                if score:
                    virus_name = virus_name.replace("a variant of ", "")
                    engine = self.md_nodes[self.current_md_node]['engine_map'][self._format_engine_name(majorkey)]
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
                    self.md_nodes[self.current_md_node]['base_url'], file_size, queue_time, processing_time, str(av_scan_times)))

        return res
