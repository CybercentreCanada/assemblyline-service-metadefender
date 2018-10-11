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
        "MD_VERSION": 4,
        'MD_TIMEOUT': 40,
        'MD_NODE_URLS': ['http://localhost:8008/'],
        'MD_NODE_API_KEYS': ['abcdefghijklmnopqrstuvwxyz']
    }

    def __init__(self, cfg=None):
        super(MetaDefender, self).__init__(cfg)
        self.dat_hash = "0"
        self.engine_map = {}
        self.engine_list = []
        self.newest_dat = epoch_to_local(0)
        self.oldest_dat = now_as_local()
        self.session = None
        self._updater_id = "ENABLE_SERVICE_BLK_MSG"
        self.timeout = cfg.get('MD_TIMEOUT', (self.SERVICE_TIMEOUT*2)/3)
        self.init_vmap = False
        self.md_node_queue_sizes = [0] * len(self.cfg.get('MD_NODE_URLS'))
        self.next_time = 0

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global requests
        import requests

    def start(self):
        self.log.debug("MetaDefender service started")
        self.session = requests.session()
        try:
            self._get_version_map()
            self.init_vmap = True
        except Exception as e:
            self.log.warn("Metadefender get_version_map failed with error code %s" % e.message)
            self.init_vmap = False

    @staticmethod
    def _format_engine_name(name):
        new_name = name.lower().replace(" ", "").replace("!", "")
        if new_name.endswith("av"):
            new_name = new_name[:-2]
        return new_name

    def _get_version_map(self):
        self.engine_map = {}
        engine_list = []
        newest_dat = 0
        oldest_dat = now()

        urls = self.cfg.get('MD_NODE_URLS') 
        url = urls[0] + "stat/engines"
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
            raise Exception("Metadefender server unaccessible.")

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
                raise Exception("Unknown metadefender version")

            # Compute newest DAT
            dat_epoch = iso_to_epoch(def_time)
            if dat_epoch > newest_dat:
                newest_dat = dat_epoch

            if dat_epoch < oldest_dat and dat_epoch != 0 and etype in ["av", "Bundled engine"]:
                oldest_dat = dat_epoch

            self.engine_map[name] = {
                'version': version,
                'def_time': iso_to_local(def_time)[:19]
            }
            engine_list.append(name)
            engine_list.append(version)
            engine_list.append(def_time)

        self.newest_dat = epoch_to_local(newest_dat)[:19]
        self.oldest_dat = epoch_to_local(oldest_dat)[:19]
        self.dat_hash = hashlib.md5("".join(engine_list)).hexdigest()

    def get_tool_version(self):
        return self.dat_hash

    def execute(self, request):
        if self.init_vmap is False:
            self._get_version_map()
            self.init_vmap = True
            
        # update queue size every 10 seconds
        if time.time() >= self.next_time:
            self.next_time = time.time() + 10
            get_queue_size()

        filename = request.download()
        response = self.scan_file(filename)
        result = self.parse_results(response)
        request.result = result
        request.set_service_context("Definition Time Range: %s - %s" % (self.oldest_dat, self.newest_dat))

    def get_scan_results_by_data_id(self, data_id, url):
        url = url + 'file/{0}'.format(data_id)
        try:
            return self.session.get(url=url, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise Exception("Metadefender service timeout.")
        except requests.ConnectionError:
            # Metadefender unaccessible
            time.sleep(10)
            raise RecoverableError('Metadefender is currently unaccessible.')
    
    def get_queue_size(self):
        self.md_node_queue_sizes = []
        urls = self.cfg.get('MD_NODE_URLS')
        api_keys = self.cfg.get('MD_NODE_API_KEYS')
        
        for i in urls:
            url = urls[i] + "stat/nodes"
            api_key = api_keys[i]
            
            try:
                r = self.session.get(url=url, headers={'apikey':api_key}, timeout=self.timeout)
            except requests.exceptions.Timeout:
                raise Exception("Metadefender service timeout.")
            except requests.ConnectionError:
                # Metadefender unaccessible
                time.sleep(10)
                raise RecoverableError('Metadefender is currently unaccessible.')
            
            if r.status_code == requests.codes.ok:
                self.md_node_queue_sizes[i] = r.json()['statuses'][0]['scan_queue']
            else:
                self.md_node_queue_sizes[i] = 'offline'
                    
    
    # choose first node in list with shortest queue
    def choose_node(self):
        node = self.md_node_queue_sizes.index(min(self.md_node_queue_sizes))
        self.md_node_queue_sizes[node] += 1
        return node
        
    def scan_file(self, filename):
        # Let's scan the file
        node = self.choose_node()
        urls = self.cfg.get('MD_NODE_URLS')
        url = urls[node]
        with open(filename, 'rb') as f:
            sample = f.read()

        try:
            r = self.session.post(url=url, data=sample, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise Exception("Metadefender service timeout.")
        except requests.ConnectionError:
            # Metadefender unaccessible
            time.sleep(10)
            raise RecoverableError('Metadefender is currently unaccessible.')

        if r.status_code == requests.codes.ok:
            data_id = r.json()['data_id']
            while True:
                r = self.get_scan_results_by_data_id(data_id=data_id, url=url)
                if r.status_code != requests.codes.ok:
					self.log.warn(r.json())
                    return r.json()
                try:
                    if r.json()['scan_results']['progress_percentage'] == 100:
                        break
                    else:
                        time.sleep(0.2)
                except KeyError:
                    # Metadefender unaccessible
                    time.sleep(10)
                    raise RecoverableError('Metadefender is currently unaccessible.')

        try:
            json_response = r.json()
            return json_response
        except:
			self.log.warn(r.json())

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
                if subdict['scan_result_i'] == 1:
                    virus_name = subdict['threat_found']
                    if virus_name:
                        score = SCORE.SURE
                elif subdict['scan_result_i'] == 2:
                    virus_name = subdict['threat_found']
                    if virus_name:
                        score = SCORE.VHIGH

                if score:
                    virus_name = virus_name.replace("a variant of ", "")
                    engine = self.engine_map[self._format_engine_name(majorkey)]
                    res.append_tag(VirusHitTag(virus_name, context="scanner:%s" % majorkey))
                    av_hits.add_section(AvHitSection(majorkey, virus_name, engine, score))
                    hit = True

            if hit:
                res.add_result(av_hits)

        return res
