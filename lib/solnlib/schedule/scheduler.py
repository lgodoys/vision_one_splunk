#
# Copyright 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import queue
import random
import threading
from time import time

import logging


class Scheduler:
    """A simple scheduler which schedules the periodic or once event."""

    import sortedcontainers as sc

    max_delay_time = 60

    def __init__(self):
        self._jobs = Scheduler.sc.SortedSet()
        self._wakeup_q = queue.Queue()
        self._lock = threading.Lock()
        self._thr = threading.Thread(target=self._do_jobs)
        # FIXME: the `daemon` property HAS to be passed in init() call ONLY,
        # the below attribute setting is of incorrect spelling
        self._thr.deamon = True
        self._started = False

    def start(self):
        """Start the schduler which will start the internal thread for
        scheduling jobs.

        Please do tear_down when doing cleanup
        """

        if self._started:
            logging.info("Scheduler already started.")
            return
        self._started = True

        self._thr.start()

    def tear_down(self):
        """Stop the schduler which will stop the internal thread for scheduling
        jobs."""

        if not self._started:
            logging.info("Scheduler already tear down.")
            return

        self._wakeup_q.put(True)

    def _do_jobs(self):
        while 1:
            (sleep_time, jobs) = self.get_ready_jobs()
            self._do_execution(jobs)
            try:
                done = self._wakeup_q.get(timeout=sleep_time)
            except queue.Empty:
                pass
            else:
                if done:
                    break
        self._started = False
        logging.info("Scheduler exited.")

    def get_ready_jobs(self):
        """
        @return: a 2 element tuple. The first element is the next ready
                 duration. The second element is ready jobs list
        """

        now = time()
        ready_jobs = []
        sleep_time = 1

        with self._lock:
            job_set = self._jobs
            total_jobs = len(job_set)
            for job in job_set:
                if job.get_expiration() <= now:
                    ready_jobs.append(job)

            if ready_jobs:
                del job_set[: len(ready_jobs)]

            for job in ready_jobs:
                if job.get_interval() != 0 and not job.stopped():
                    # repeated job, calculate next due time and enqueue
                    job.update_expiration()
                    job_set.add(job)

            if job_set:
                sleep_time = job_set[0].get_expiration() - now
                if sleep_time < 0:
                    logging.warn("Scheduler satuation, sleep_time=%s", sleep_time)
                    sleep_time = 0.1

        if ready_jobs:
            logging.info(
                "Get %d ready jobs, next duration is %f, "
                "and there are %s jobs scheduling",
                len(ready_jobs),
                sleep_time,
                total_jobs,
            )

        ready_jobs.sort(key=lambda job: job.get("priority", 0), reverse=True)
        return (sleep_time, ready_jobs)

    def add_jobs(self, jobs):
        with self._lock:
            now = time()
            job_set = self._jobs
            for job in jobs:
                delay_time = random.randrange(0, self.max_delay_time)
                job.set_initial_due_time(now + delay_time)
                job_set.add(job)
        self._wakeup()

    def update_jobs(self, jobs):
        with self._lock:
            job_set = self._jobs
            for njob in jobs:
                job_set.discard(njob)
                job_set.add(njob)
        self._wakeup()

    def remove_jobs(self, jobs):
        with self._lock:
            job_set = self._jobs
            for njob in jobs:
                njob.stop()
                job_set.discard(njob)
        self._wakeup()

    def number_of_jobs(self):
        with self._lock:
            return len(self._jobs)

    def disable_randomization(self):
        self.max_delay_time = 1

    def _wakeup(self):
        self._wakeup_q.put(None)

    def _do_execution(self, jobs):
        for job in jobs:
            job()
