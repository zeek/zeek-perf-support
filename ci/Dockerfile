FROM zeek/zeek:7.0

RUN apt-get update && apt-get install --no-install-recommends -y \
	build-essential \
	cmake \
	libpcap-dev \
	libssl-dev

WORKDIR /zeek-perf-support

COPY ./ .

RUN git config --global --add safe.directory $(pwd)
RUN git status .
RUN yes | zkg install .
RUN zeek -N Zeek::PerfSupport
RUN zeek PerfSupport::enable=T -e 'event zeek_init() {}'
RUN cat /tmp/perf-*.map
