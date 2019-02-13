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
        title = '%s identified the file as %s' % (av_name, virus_name)
        body = ""
        if engine:
            body = "Engine: %s :: Definition: %s " % (engine['version'], engine['def_time'])
        super(AvHitSection, self).__init__(
            title_text=title,
            score=score,
            body=body,
            classification=Classification.UNRESTRICTED
        )


class AvErrorSection(ResultSection):
    def __init__(self, av_name, engine, score):
        title = '%s failed to scan the file' % av_name
        body = ""
        if engine:
            body = "Engine: %s :: Definition: %s " % (engine['version'], engine['def_time'])
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
        if type(self.cfg.get('BASE_URL')) != list:
            base_urls = [self.cfg.get('BASE_URL')]
        else:
            for base_url in self.cfg.get('BASE_URL'):
                base_urls.append(base_url)

        for index, url in enumerate(base_urls):
            self.md_nodes[index] = {'base_url': url,
                                    'timeout_count': 0,
                                    'timeout': 0,
                                    'engine_map': {},
                                    'newest_dat': epoch_to_local(0),
                                    'oldest_dat': now_as_local()
                                    }

        self.session = requests.session()
        self._get_version_map()

    @staticmethod
    def _format_engine_name(name):
        new_name = name.lower().replace(" ", "").replace("!", "")
        if new_name.endswith("av"):
            new_name = new_name[:-2]
        return new_name

    def _get_version_map(self):
        newest_dat = 0
        oldest_dat = now()

        for i in range(len(self.md_nodes)):
            engine_list = []
            url = self.md_nodes[i]['base_url'] + "stat/engines"

            done = False
            retries = 0
            max_retry = 5
            r = None
            while not done:
                try:
                    r = self.session.get(url=url, timeout=self.timeout)
                    done = True
                except requests.exceptions.Timeout:
                    if retries > max_retry:
                        done = True
                except requests.ConnectionError:
                    if retries > max_retry:
                        done = True

                if not r:
                    retries += 1
                    time.sleep(10)

            if not r:
                continue

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
                    def_time = engine['def_time'].replace(" AM", "").replace(" PM", "").replace("/", "-").replace(" ", "T")
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

            self.md_nodes[i]['newest_dat'] = epoch_to_local(newest_dat)[:19]
            self.md_nodes[i]['oldest_dat'] = epoch_to_local(oldest_dat)[:19]

        count = 0
        for i in self.md_nodes.values():
            count += len(i['engine_map'])

        if count == 0:
            raise Exception("Unable to reach any MetaDefender node to get version map")

    def get_tool_version(self):
        engine_maps = []
        for i in range(len(self.md_nodes)):
            engine_maps.append(self.md_nodes[i]['engine_map'])

        return hashlib.md5("".join(engine_maps)).hexdigest()

    def execute(self, request):
        if len(self.md_nodes[self.current_md_node]['engine_map']) == 0:
            try:
                self._get_version_map()
            except:
                self.deactivate_node()

        filename = request.download()
        response = self.scan_file(filename)
        result = self.parse_results(response)
        request.result = result
        request.set_service_context("Definition Time Range: %s - %s" % (self.md_nodes[self.current_md_node]['oldest_dat'],
                                                                        self.md_nodes[self.current_md_node]['newest_dat']))

    def get_scan_results_by_data_id(self, data_id):
        base_url = self.md_nodes[self.current_md_node]['base_url']
        url = base_url + 'file/{0}'.format(data_id)

        try:
            return self.session.get(url=url, timeout=self.timeout)
        except requests.exceptions.Timeout:
            self.deactivate_node()
            raise Exception("MetaDefender node (%s) timeout" % self.md_nodes[self.current_md_node]['base_url'])
        except requests.ConnectionError:
            # MetaDefender inaccessible
            if len(self.md_nodes) == 1:
                time.sleep(5)
            self.deactivate_node()
            raise RecoverableError("Unable to reach MetaDefender node (%s)" % self.md_nodes[self.current_md_node]['base_url'])

    def deactivate_node(self):
        if len(self.md_nodes) > 1:
            if self.md_nodes[self.current_md_node]['timeout_count'] <= 5:
                self.md_nodes[self.current_md_node]['timeout_count'] += 1
                self.md_nodes[self.current_md_node]['timeout'] = self.md_nodes[self.current_md_node]['timeout_count']

    def next_node(self):
        if self.current_md_node == len(self.md_nodes)-1:
            self.current_md_node = 0
        else:
            self.current_md_node += 1

        while True:
            if self.md_nodes[self.current_md_node]['timeout'] == 0:
                break
            else:
                self.md_nodes[self.current_md_node]['timeout'] -= 1
                self.current_md_node += 1

            if self.current_md_node == len(self.md_nodes):
                self.current_md_node = 0

    def scan_file(self, filename):
        # Let's scan the file
        base_url = self.md_nodes[self.current_md_node]['base_url']
        url = base_url + "file"
        with open(filename, 'rb') as f:
            sample = f.read()

        try:
            start_time = time.time()
            r = self.session.post(url=url, data=sample, timeout=self.timeout)
        except requests.exceptions.Timeout:
            self.deactivate_node()
            raise Exception("MetaDefender node (%s) timeout" % self.md_nodes[self.current_md_node]['base_url'])
        except requests.ConnectionError:
            # MetaDefender inaccessible
            if len(self.md_nodes) == 1:
                time.sleep(5)
            self.deactivate_node()
            raise RecoverableError("Unable to reach MetaDefender node (%s)" % self.md_nodes[self.current_md_node]['base_url'])

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
                    raise RecoverableError("Unable to reach MetaDefender node (%s)" % self.md_nodes[self.current_md_node]['base_url'])

            if (time.time() - start_time) > self.cfg.get('MAX_MD_SCAN_TIME'):
                self.deactivate_node()
            else:
                self.md_nodes[self.current_md_node]['timeout_count'] = 0
                self.md_nodes[self.current_md_node]['timeout'] = 0

        if len(self.md_nodes) > 1:
            self.next_node()
        json_response = r.json()

        return json_response

    def parse_results(self, response):
        res = Result()
        response = response.get('scan_results', response)
        virus_name = ""

        if response is not None and response.get('progress_percentage') == 100:
            hit = False
            av_hits = ResultSection(title_text='Anti-Virus Detections')

            scans = response.get('scan_details', response)
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
                    res.append_tag(VirusHitTag(virus_name, context="scanner:%s" % majorkey))
                    av_hits.add_section(AvHitSection(majorkey, virus_name, engine, score))
                    hit = True
                    
            if hit:
                res.add_result(av_hits)

        return res
