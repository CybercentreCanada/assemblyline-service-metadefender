import hashlib
import random
import time
from typing import Dict, Any
from urllib.parse import urljoin
import json

import requests

from assemblyline.common.exceptions import RecoverableError
from assemblyline.common.isotime import iso_to_local, iso_to_epoch, epoch_to_local, now, now_as_local
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name, engine, heur_id: int):
        title = f"{av_name} identified the file as {virus_name}"
        json_body = dict(
            av_name=av_name,
            virus_name=virus_name,
            scan_result="infected" if heur_id == 1 else "suspicious",
            engine_version=engine['version'] if engine else "unknown",
            engine_definition_time=engine['def_time'] if engine else "unknown",
        )

        # body = f"Engine: {engine['version']} :: Definition: {engine['def_time']}" if engine else ""
        super(AvHitSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.JSON,
            body=json.dumps(json_body),
            classification=Classification.UNRESTRICTED,
        )


class AvErrorSection(ResultSection):
    def __init__(self, av_name, engine):
        title = f"{av_name} failed to scan the file"
        body = f"Engine: {engine['version']} :: Definition: {engine['def_time']}" if engine else ""
        super(AvErrorSection, self).__init__(
            title_text=title,
            body=body,
            classification=Classification.UNRESTRICTED
        )


class MetaDefender(ServiceBase):
    def __init__(self, config=None):
        super(MetaDefender, self).__init__(config)
        self.session = None
        self.timeout = self.config.get("md_timeout", (40*2)/3)
        self.nodes = {}
        self.current_node = None
        self.start_time = None

    def start(self):
        self.log.debug("MetaDefender service started")
        base_urls = []
        if type(self.config.get("base_url")) == str:
            base_urls = [self.config.get("base_url")]
        elif type(self.config.get("base_url")) == list:
            for base_url in self.config.get("base_url"):
                base_urls.append(base_url)
        else:
            raise Exception("Invalid format for BASE_URL service variable (must be str or list)")

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
        for node in list(self.nodes.keys()):
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
                    self.log.info(f"Node ({self.current_node}) chosen at launch")
                    break
                else:
                    self._get_version_map(self.current_node)

        # Start the global timer
        if not self.start_time:
            self.start_time = time.time()

    @staticmethod
    def _format_engine_name(name: str):
        new_name = name.lower().replace(" ", "").replace("!", "")
        if new_name.endswith("av"):
            new_name = new_name[:-2]
        return new_name

    def _get_version_map(self, node: str):
        newest_dat = 0
        oldest_dat = now()
        engine_list = []
        url = urljoin(node, 'stat/engines')

        try:
            r = self.session.get(url=url, timeout=self.timeout)
            engines = r.json()

            for engine in engines:
                if self.config.get("md_version") == 4:
                    name = self._format_engine_name(engine["eng_name"])
                    version = engine['eng_ver']
                    def_time = engine['def_time']
                    etype = engine['engine_type']
                elif self.config.get("md_version") == 3:
                    name = self._format_engine_name(engine["eng_name"]).replace("scanengine", "")
                    version = engine['eng_ver']
                    def_time = engine['def_time'].replace(" AM", "").replace(" PM", "").replace("/", "-").replace(" ",
                                                                                                                  "T")
                    def_time = def_time[6:10] + "-" + def_time[:5] + def_time[10:] + "Z"
                    etype = engine['eng_type']
                else:
                    raise Exception("Unknown version of MetaDefender")

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
            self.log.warning(f"Node ({node}) timed out after {self.timeout}s "
                             "while trying to get engine version map")
        except requests.ConnectionError:
            self.log.warning(f"Unable to connect to node ({node}) while trying to get engine version map")

    def get_tool_version(self):
        engine_lists = ""
        for node in list(self.nodes.keys()):
            engine_lists += self.nodes[node]['engine_list']
        return hashlib.md5(engine_lists.encode('utf-8')).hexdigest()

    def execute(self, request: ServiceRequest):
        # Check that the current node has a version map
        while True:
            if self.nodes[self.current_node]['engine_count'] == 0:
                self._get_version_map(self.current_node)
                self.log.info("Getting version map from execute() function")
                if self.nodes[self.current_node]['engine_count'] == 0:
                    self.new_node(force=True)
            else:
                break

        filename = request.file_path
        try:
            response = self.scan_file(filename)
        except RecoverableError:
            response = self.scan_file(filename)
        result = self.parse_results(response)
        request.result = result
        request.set_service_context(f"Definition Time Range: {self.nodes[self.current_node]['oldest_dat']} - "
                                    f"{self.nodes[self.current_node]['newest_dat']}")

        # Compare queue time of current node with new random node after a minimum run time on current node
        elapsed_time = self.start_time - time.time()
        if elapsed_time >= self.config.get("max_node_time"):
            self.new_node(force=True)
        elif elapsed_time >= self.config.get("min_node_time"):
            self.new_node(force=False)

    def get_scan_results_by_data_id(self, data_id: str):
        url = urljoin(self.current_node, f"file/{data_id}")

        try:
            return self.session.get(url=url, timeout=self.timeout)
        except requests.exceptions.Timeout:
            self.new_node(force=True, reset_queue=True)
            raise Exception(f"Node ({self.current_node}) timed out after {self.timeout}s "
                            "while trying to fetch scan results")
        except requests.ConnectionError:
            # MetaDefender inaccessible
            self.new_node(force=True, reset_queue=True)
            raise RecoverableError(f"Unable to reach node ({self.current_node}) while trying to fetch scan results")

    def new_node(self, force, reset_queue=False):
        if len(self.nodes) == 1:
            time.sleep(5)
            return

        # Close the requests session before moving on to select new node
        self.session.close()

        if self.nodes[self.current_node]['file_count'] > 1:
            average = sum(self.nodes[self.current_node]['queue_times']) / self.nodes[self.current_node]['file_count']

            # Reset the average queue time, when connection or timeout error
            if reset_queue:
                self.nodes[self.current_node]['average_queue_time'] = 0
            else:
                self.nodes[self.current_node]['average_queue_time'] = average
            self.nodes[self.current_node]['file_count'] = 0

            while True:
                temp_node = random.choice(list(self.nodes.keys()))
                if temp_node != self.current_node:
                    if force:
                        self.log.info(f"Changed node from {self.current_node} to {temp_node}")
                        self.current_node = temp_node
                        self.start_time = time.time()
                        return
                    else:
                        # Only change to new node if the current node's average queue time is larger than the new node
                        if average > self.nodes[temp_node]['average_queue_time']:
                            self.log.info(f"Changed node from {self.current_node} to {temp_node}")
                            self.current_node = temp_node

                        # Reset the start time
                        self.start_time = time.time()
                        return

    def scan_file(self, filename: str):
        # Let's scan the file
        url = urljoin(self.current_node, 'file')
        with open(filename, 'rb') as f:
            data = f.read()

        try:
            r = self.session.post(url=url, data=data, timeout=self.timeout)
        except requests.exceptions.Timeout:
            self.new_node(force=True, reset_queue=True)
            raise Exception(f"Node ({self.current_node}) timed out after {self.timeout}s "
                            "while trying to send file for scanning")
        except requests.ConnectionError:
            # MetaDefender inaccessible
            self.new_node(force=True, reset_queue=True)  # Deactivate the current node which had a connection error
            raise RecoverableError(
                f"Unable to reach node ({self.current_node}) while trying to send file for scanning")

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
                    self.new_node(force=True, reset_queue=True)
                    raise RecoverableError(
                        f"Unable to reach node ({self.current_node}) while trying to fetch scan results")

            self.nodes[self.current_node]['timeout_count'] = 0
            self.nodes[self.current_node]['timeout'] = 0

        return r.json()

    def parse_results(self, response: Dict[str, Any]):
        res = Result()
        scan_results = response.get('scan_results', response)
        virus_name = ""

        if scan_results is not None and scan_results.get('progress_percentage') == 100:
            hit = False
            av_hits = ResultSection('Anti-Virus Detections')

            scans = scan_results.get('scan_details', scan_results)
            av_scan_times = []
            for majorkey, subdict in sorted(scans.items()):
                heur_id = None
                if subdict['scan_result_i'] == 1:           # File is infected
                    virus_name = subdict['threat_found']
                    if virus_name:
                        heur_id = 1
                elif subdict['scan_result_i'] == 2:         # File is suspicious
                    virus_name = subdict['threat_found']
                    if virus_name:
                        heur_id = 2
                elif subdict['scan_result_i'] == 10 or subdict['scan_result_i'] == 3:   # File was not scanned or failed
                    try:
                        engine = self.nodes[self.current_node]['engine_map'][self._format_engine_name(majorkey)]
                    except:
                        engine = None
                    av_hits.add_subsection(AvErrorSection(majorkey, engine))
                    hit = True

                if heur_id is not None:
                    virus_name = virus_name.replace("a variant of ", "")
                    engine = self.nodes[self.current_node]['engine_map'][self._format_engine_name(majorkey)]
                    av_hit_section = AvHitSection(majorkey, virus_name, engine, heur_id)
                    av_hit_section.set_heuristic(heur_id, signature=f'{majorkey}.{virus_name}')
                    av_hit_section.add_tag('av.virus_name', virus_name)
                    av_hits.add_subsection(av_hit_section)
                    hit = True

                av_scan_times.append(self._format_engine_name(majorkey))
                av_scan_times.append(subdict['scan_time'])

            if hit:
                res.add_section(av_hits)

            file_size = response['file_info']['file_size']
            queue_time = response['process_info']['queue_time']
            processing_time = response['process_info']['processing_time']
            self.log.info(f"File successfully scanned by node ({self.current_node}). File size: {file_size} B."
                          f"Queue time: {queue_time} ms. Processing time: {processing_time} ms. "
                          f"AV scan times: {str(av_scan_times)}")

            # Add the queue time to a list, which will be later used to calculate average queue time
            self.nodes[self.current_node]['queue_times'].append(queue_time)
            self.nodes[self.current_node]['file_count'] += 1

        return res
